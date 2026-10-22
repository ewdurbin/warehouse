# SPDX-License-Identifier: Apache-2.0

import types

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

import jwt
import pytest

from freezegun import freeze_time
from pyramid import testing
from pyramid.exceptions import ConfigurationError
from pyramid.request import Request, apply_request_extensions
from sqlalchemy import func, select
from zope.interface.verify import verifyClass

from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from tests.common.jwt import API_AUDIENCE, ISSUER, UPLOAD_AUDIENCE
from warehouse.accounts import _oidc_claims
from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTSigner, IJWTVerifier
from warehouse.jwt.issuer import WarehouseJWTIssuer, WarehouseJWTIssuerFactory
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.jwt.services import DisabledJWTIssuer, jwt_issuer_factory
from warehouse.jwt.verifier import WarehouseJWTVerifier
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import MultiSecurityPolicy

AUDIENCES = {"upload": UPLOAD_AUDIENCE, "api": API_AUDIENCE}


@pytest.fixture
def clock():
    with freeze_time("2026-10-22 00:00:00.123456+00:00", ignore=["_pytest"]) as clock:
        yield clock


@pytest.fixture
def signing_config():
    return WarehouseJWTIssuerFactory(issuer=ISSUER, audiences=AUDIENCES)


@pytest.fixture
def issuer(signing_config, jwt_registry, warehouse_jwt_signer):
    return WarehouseJWTIssuer(
        registry=jwt_registry, signer=warehouse_jwt_signer, config=signing_config
    )


@pytest.fixture
def issue_args(verified):
    return {
        "subject": verified.subject,
        "audience": "upload",
        "authorization_details": verified.authorization_details,
    }


class TestDisabledJWTIssuer:
    def test_interface(self):
        assert verifyClass(IJWTIssuer, DisabledJWTIssuer)

    def test_default_needs_no_configuration(self, issue_args):
        factory = jwt_issuer_factory({})
        assert factory == DisabledJWTIssuer.create_service
        with pytest.raises(RuntimeError, match="JWT issuance is disabled"):
            factory(None, None).issue(**issue_args)

    def test_verification_only_needs_no_signing_access(self, warehouse_jwt_settings):
        del warehouse_jwt_settings["warehouse.jwt.kms_key_id"]
        del warehouse_jwt_settings["warehouse.jwt.signing_key_id"]
        assert (
            jwt_issuer_factory(warehouse_jwt_settings)
            == DisabledJWTIssuer.create_service
        )


class TestWarehouseJWTIssuerFactory:
    @pytest.mark.parametrize(
        "missing", ["kms_key_id", "signing_key_id", "verification_keys"]
    )
    def test_incomplete_signing_configuration_fails_startup(
        self, warehouse_jwt_settings, missing
    ):
        del warehouse_jwt_settings[f"warehouse.jwt.{missing}"]
        with testing.testConfig(settings=warehouse_jwt_settings) as config:
            config.include("pyramid_services")
            with pytest.raises(ConfigurationError, match="KMS key and a key ID"):
                config.include("warehouse.jwt")

    def test_service_registration(
        self,
        warehouse_jwt_settings,
        warehouse_jwt_signer,
        db_session,
        issue_args,
        clock,
        mocker,
    ):
        mocker.patch(
            "warehouse.jwt.KMSJWTSignerService.from_settings",
            return_value=warehouse_jwt_signer,
        )
        with testing.testConfig(settings=warehouse_jwt_settings) as config:
            config.include("pyramid_services")
            config.add_directive("add_periodic_task", mocker.Mock())
            config.include("warehouse.jwt")
            config.commit()
            request = Request.blank("/exchange")
            request.registry = config.registry
            request.db = db_session
            apply_request_extensions(request)
            assert (
                request.find_service(IJWTSigner, context=None) is warehouse_jwt_signer
            )
            issuer = request.find_service(IJWTIssuer, context=None)
            assert isinstance(issuer, WarehouseJWTIssuer)
            issued = issuer.issue(**issue_args)
            registry = request.find_service(IJWTRegistry, context=None)
            assert registry.is_active(issued.jti)

    def test_immutable_configuration(self):
        audiences = dict(AUDIENCES)
        factory = WarehouseJWTIssuerFactory(issuer=ISSUER, audiences=audiences)
        audiences["upload"] = "changed"
        assert factory.audiences == AUDIENCES
        with pytest.raises(TypeError):
            factory.audiences["upload"] = "changed"
        with pytest.raises(FrozenInstanceError):
            factory.issuer = "changed"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("issuer", None),
            ("issuer", ""),
            ("issuer", []),
            ("audiences", None),
            ("audiences", {}),
            ("audiences", []),
            ("audiences", {"upload": ""}),
            ("audiences", {"upload": []}),
            ("audiences", {"": "audience"}),
            ("audiences", {1: "audience"}),
            ("audiences", {"upload": "same", "api": "same"}),
        ],
    )
    def test_invalid_configuration(self, signing_config, field, value):
        with pytest.raises(ValueError, match="JWT"):
            replace(signing_config, **{field: value})

    @pytest.mark.parametrize("setting", ["issuer", "upload_audience", "api_audience"])
    def test_missing_configuration(self, warehouse_jwt_settings, setting):
        del warehouse_jwt_settings[f"warehouse.jwt.{setting}"]
        with pytest.raises(ConfigurationError, match="JWT"):
            jwt_issuer_factory(warehouse_jwt_settings)


class TestWarehouseJWTIssuer:
    def test_interface(self):
        assert verifyClass(IJWTIssuer, WarehouseJWTIssuer)

    @pytest.mark.parametrize("kind", [SubjectKind.USER, SubjectKind.PUBLISHER])
    @pytest.mark.parametrize("audience", ["upload", "api"])
    @pytest.mark.parametrize("lifetime", [1, 300])
    def test_signed_roundtrip(
        self,
        issuer,
        warehouse_jwt_key,
        jwt_registry,
        issue_args,
        clock,
        kind,
        audience,
        lifetime,
    ):
        issue_args.update(
            subject=replace(issue_args["subject"], kind=kind),
            audience=audience,
            lifetime=lifetime,
            additional={"oidc": {"sha": "abc"}},
        )
        issued = issuer.issue(**issue_args)
        verifier = WarehouseJWTVerifier(
            issuer=ISSUER,
            audience=AUDIENCES[audience],
            keys={"current": warehouse_jwt_key.public_key()},
        )
        verified = verifier.verify(issued.token)
        assert verified is not None
        assert verified.subject == issue_args["subject"]
        assert verified.authorization_details == issue_args["authorization_details"]
        assert verified.issuer == ISSUER
        assert verified.audience == AUDIENCES[audience]
        assert verified.jti == issued.jti
        assert issued.jti.version == 7
        assert verified.expires_at == issued.expires_at
        assert verified.expires_at - verified.issued_at == timedelta(seconds=lifetime)
        assert verified.issued_at == datetime.now(UTC).replace(microsecond=0)
        entry = jwt_registry.get_active(issued.jti)
        assert entry.expires_at == issued.expires_at
        assert entry.additional == {"oidc": {"sha": "abc"}}
        assert jwt.get_unverified_header(issued.token) == {
            "alg": "RS256",
            "typ": "pypi-access+jwt",
            "kid": "current",
        }
        claims = jwt.decode(
            issued.token,
            warehouse_jwt_key.public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCES[audience],
        )
        assert set(claims) == {
            "iss",
            "aud",
            "sub",
            "subject_kind",
            "iat",
            "exp",
            "jti",
            "authorization_details",
        }
        assert issued.token not in repr(issued)
        with pytest.raises(FrozenInstanceError):
            issued.token = "changed"
        assert issuer.issue(**issue_args).jti != issued.jti

        other = "api" if audience == "upload" else "upload"
        wrong_audience = WarehouseJWTVerifier(
            issuer=ISSUER,
            audience=AUDIENCES[other],
            keys={"current": warehouse_jwt_key.public_key()},
        )
        assert wrong_audience.verify(issued.token) is None
        clock.move_to(issued.expires_at)
        assert verifier.verify(issued.token) is None
        assert jwt_registry.get_active(issued.jti) is None

    @pytest.mark.parametrize("lifetime", [0, -1, 301, 1.5, True, "300", None])
    def test_invalid_lifetime(self, issuer, issue_args, lifetime, mocker):
        register = mocker.spy(issuer.registry, "register")
        with pytest.raises(ValueError, match="lifetime"):
            issuer.issue(**issue_args, lifetime=lifetime)
        register.assert_not_called()

    @pytest.mark.parametrize(
        "audience", ["unknown", AUDIENCES["upload"], ["upload"], None]
    )
    def test_unknown_audience(self, issuer, issue_args, audience, mocker):
        register = mocker.spy(issuer.registry, "register")
        issue_args["audience"] = audience
        with pytest.raises(ValueError, match="audience"):
            issuer.issue(**issue_args)
        register.assert_not_called()

    @pytest.mark.parametrize(
        "subject",
        [
            None,
            {},
            SubjectRef("organization", uuid7()),
            SubjectRef(SubjectKind.USER, "not-a-uuid"),
        ],
    )
    def test_invalid_subject(self, issuer, issue_args, subject, mocker):
        register = mocker.spy(issuer.registry, "register")
        issue_args["subject"] = subject
        with pytest.raises(ValueError, match="subject"):
            issuer.issue(**issue_args)
        register.assert_not_called()

    @pytest.mark.parametrize(
        "details",
        [
            None,
            [],
            (),
            ({},),
            (AuthorizationDetail(AuthorizationType.WAREHOUSE, []),),
            (AuthorizationDetail("unknown", (Permissions.ProjectsUpload,)),),
            (AuthorizationDetail(AuthorizationType.WAREHOUSE, ()),),
            (
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE, (Permissions.AccountManage,)
                ),
            ),
            (AuthorizationDetail(AuthorizationType.WAREHOUSE, ("unknown",)),),
            (
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,), {}
                ),
            ),
            (
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.ProjectsUpload,),
                    ResourceRef(ResourceKind.PROJECT, "not-a-uuid"),
                ),
            ),
            (
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.ProjectsUpload,),
                    ResourceRef("organization", UUID(int=1)),
                ),
            ),
            (
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.APIEcho,),
                    ResourceRef(ResourceKind.PROJECT, UUID(int=1)),
                ),
            ),
        ],
    )
    def test_invalid_authorization_details(self, issuer, issue_args, details, mocker):
        register = mocker.spy(issuer.registry, "register")
        issue_args["authorization_details"] = details
        with pytest.raises(ValueError, match="JWT"):
            issuer.issue(**issue_args)
        register.assert_not_called()

    def test_issuance_rollback(self, issuer, issue_args, db_session, clock):
        with db_session.begin_nested() as transaction:
            issued = issuer.issue(**issue_args, additional={"oidc": {"sha": "abc"}})
            assert issuer.registry.is_active(issued.jti)
            transaction.rollback()
        assert issuer.registry.get_active(issued.jti) is None

    def test_signing_failure_rolls_back_with_caller(
        self, issuer, issue_args, db_session, clock, mocker
    ):
        mocker.patch.object(
            type(issuer.signer), "sign", side_effect=RuntimeError("signing failed")
        )
        with (
            pytest.raises(RuntimeError, match="signing failed"),
            db_session.begin_nested(),
        ):
            issuer.issue(**issue_args)
        assert db_session.scalar(select(func.count()).select_from(IssuedJWT)) == 0

    def test_registry_failure_does_not_sign(self, issuer, issue_args, clock, mocker):
        mocker.patch.object(
            issuer.registry,
            "register",
            side_effect=RuntimeError("database unavailable"),
        )
        sign = mocker.spy(type(issuer.signer), "sign")
        with pytest.raises(RuntimeError, match="database unavailable"):
            issuer.issue(**issue_args)
        sign.assert_not_called()

    @pytest.mark.parametrize("narrow", [False, True])
    def test_publisher_metadata_and_live_authorization(
        self, issuer, jwt_registry, db_session, warehouse_jwt_key, clock, narrow
    ):
        publisher = GitHubPublisherFactory()
        projects = [ProjectFactory(oidc_publishers=[publisher]) for _ in range(3)]
        detail = AuthorizationDetail(
            AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,)
        )
        details = (
            tuple(
                replace(detail, resource=ResourceRef(ResourceKind.PROJECT, project.id))
                for project in projects[:2]
            )
            if narrow
            else (detail,)
        )
        metadata = {"sha": "abc", "ref": "refs/tags/v1"}
        issued = issuer.issue(
            subject=SubjectRef(SubjectKind.PUBLISHER, publisher.id),
            audience="upload",
            authorization_details=details,
            additional={
                "oidc": metadata,
                "authorization_details": [{"actions": ["*"]}],
            },
        )
        verifier = WarehouseJWTVerifier(
            issuer=ISSUER,
            audience=AUDIENCES["upload"],
            keys={"current": warehouse_jwt_key.public_key()},
        )
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service(verifier, IJWTVerifier)
            config.register_service(jwt_registry, IJWTRegistry)
            config.add_request_method(_oidc_claims, "oidc_claims", reify=True)
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/legacy/")
            request.registry = config.registry
            request.db = db_session
            apply_request_extensions(request)
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"jwt"}, None)]
            )
            request.headers["Authorization"] = f"Bearer {issued.token}"
            assert request.identity.publisher is publisher
            assert request.oidc_claims == metadata
            assert publisher.publisher_url(request.oidc_claims).endswith("/commit/abc")
            assert request.has_permission(Permissions.ProjectsUpload, projects[0])
            assert request.has_permission(Permissions.ProjectsUpload, projects[1])
            assert (
                bool(request.has_permission(Permissions.ProjectsUpload, projects[2]))
                is not narrow
            )
            assert not request.has_permission(
                Permissions.ProjectsUpload, ProjectFactory()
            )
            assert not request.has_permission(
                Permissions.APIObservationsAdd, projects[0]
            )
            jwt_registry.revoke(issued.jti)
            assert not request.has_permission(Permissions.ProjectsUpload, projects[0])
