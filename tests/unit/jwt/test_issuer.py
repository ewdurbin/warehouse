# SPDX-License-Identifier: Apache-2.0

from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from pyramid import testing
from pyramid.exceptions import ConfigurationError
from pyramid.request import Request, apply_request_extensions
from sqlalchemy import func, select
from zope.interface.verify import verifyClass

from tests.common.jwt import API_AUDIENCE, ISSUER, PROJECT_ID, UPLOAD_AUDIENCE
from tests.conftest import get_app_config
from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.interfaces import IJWTIssuer, IJWTSigner, IJWTVerifier
from warehouse.jwt.issuer import WarehouseJWTIssuer, WarehouseJWTIssuerFactory
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS
from warehouse.jwt.services import DisabledJWTIssuer
from warehouse.jwt.signing import KMSJWTSignerService
from warehouse.jwt.verifier import WarehouseJWTVerifier

AUDIENCES = {"upload": UPLOAD_AUDIENCE, "api": API_AUDIENCE}


@pytest.fixture
def issuer(jwt_registry, warehouse_jwt_signer):
    return WarehouseJWTIssuer(
        registry=jwt_registry,
        signer=warehouse_jwt_signer,
        config=WarehouseJWTIssuerFactory(issuer=ISSUER, audiences=AUDIENCES),
    )


@pytest.fixture
def issue_args():
    return {
        "subject": SubjectRef(SubjectKind.PUBLISHER, uuid4()),
        "audience": "upload",
        "authorization_details": (
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,)
            ),
        ),
    }


@pytest.mark.parametrize("service", [DisabledJWTIssuer, WarehouseJWTIssuer])
def test_issuer_interface(service):
    assert verifyClass(IJWTIssuer, service)


def test_verification_only_needs_no_signing_access(make_request, sign, issue_args):
    token = sign()
    request = make_request("/danger-api/echo", token)
    issuer = request.find_service(IJWTIssuer, context=None)

    assert not issuer.enabled
    with pytest.raises(RuntimeError, match="JWT issuance is disabled"):
        issuer.issue(**issue_args)
    assert request.find_service(IJWTVerifier, context=None).verify(token) is not None


@pytest.mark.parametrize(
    "missing", ["kms_key_id", "signing_key_id", "verification_keys"]
)
def test_incomplete_signing_configuration_fails_startup(
    warehouse_jwt_settings, missing
):
    del warehouse_jwt_settings[f"warehouse.jwt.{missing}"]
    with testing.testConfig(settings=warehouse_jwt_settings) as config:
        config.include("pyramid_services")
        with pytest.raises(ConfigurationError, match="KMS key and a key ID"):
            config.include("warehouse.jwt")


def test_registers_configured_issuer(
    database, db_session, warehouse_jwt_settings, warehouse_jwt_signer, mocker
):
    mocker.patch.object(
        KMSJWTSignerService, "from_settings", return_value=warehouse_jwt_signer
    )
    config = get_app_config(database, warehouse_jwt_settings)
    try:
        request = Request.blank("/exchange")
        request.registry = config.registry
        request.db = db_session
        apply_request_extensions(request)

        assert request.find_service(IJWTSigner, context=None) is warehouse_jwt_signer
        assert request.find_service(IJWTIssuer, context=None).enabled
    finally:
        config.registry["sqlalchemy.engine"].dispose()


@pytest.mark.usefixtures("clock")
@pytest.mark.parametrize(
    ("audience", "kind", "detail"),
    [
        (
            "upload",
            SubjectKind.PUBLISHER,
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE,
                (Permissions.ProjectsUpload,),
                ResourceRef(ResourceKind.PROJECT, UUID(PROJECT_ID)),
            ),
        ),
        (
            "api",
            SubjectKind.USER,
            AuthorizationDetail(AuthorizationType.WAREHOUSE, (Permissions.APIEcho,)),
        ),
    ],
    ids=["publisher-upload", "user-api"],
)
def test_signed_roundtrip(
    issuer, warehouse_jwt_key, jwt_registry, audience, kind, detail
):
    subject = SubjectRef(kind, uuid4())
    additional = {
        "oidc": {"sha": "abc"},
        "authorization_details": [{"actions": ["*"]}],
    }
    issued = issuer.issue(
        subject=subject,
        audience=audience,
        authorization_details=(detail,),
        additional=additional,
    )

    verifier = WarehouseJWTVerifier(
        issuer=ISSUER,
        audience=AUDIENCES[audience],
        keys={"current": warehouse_jwt_key.public_key()},
    )
    verified = verifier.verify(issued.token)
    assert verified is not None
    assert verified.subject == subject
    assert verified.authorization_details == (detail,)
    assert verified.jti == issued.jti
    assert verified.expires_at == issued.expires_at
    assert verified.expires_at - verified.issued_at == timedelta(
        seconds=MAX_LIFETIME_SECONDS
    )
    assert issued.token not in repr(issued)

    entry = jwt_registry.get_active(issued.jti)
    assert entry.expires_at == issued.expires_at
    assert entry.additional == additional


@pytest.mark.parametrize("lifetime", [0, MAX_LIFETIME_SECONDS + 1, True])
def test_rejects_invalid_lifetime(issuer, issue_args, lifetime):
    with pytest.raises(ValueError, match="JWT lifetime"):
        issuer.issue(**issue_args, lifetime=lifetime)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        pytest.param({"audience": UPLOAD_AUDIENCE}, "audience name", id="audience-url"),
        pytest.param(
            {"subject": SubjectRef(SubjectKind.PUBLISHER, "not-a-uuid")},
            "JWT subject",
            id="invalid-subject",
        ),
        pytest.param(
            {
                "authorization_details": (
                    AuthorizationDetail(
                        AuthorizationType.WAREHOUSE, (Permissions.AccountManage,)
                    ),
                ),
            },
            "authorization details",
            id="unsupported-action",
        ),
    ],
)
def test_rejects_invalid_claims(issuer, issue_args, db_session, overrides, message):
    with pytest.raises(ValueError, match=message):
        issuer.issue(**(issue_args | overrides))
    assert db_session.scalar(select(func.count()).select_from(IssuedJWT)) == 0


@pytest.mark.usefixtures("clock")
def test_oversized_token_rolls_back_with_caller(issuer, issue_args, db_session):
    issue_args["authorization_details"] *= 200
    with (
        pytest.raises(ValueError, match="maximum token length"),
        db_session.begin_nested(),
    ):
        issuer.issue(**issue_args)
    assert db_session.scalar(select(func.count()).select_from(IssuedJWT)) == 0


@pytest.mark.usefixtures("clock")
def test_signing_failure_rolls_back_with_caller(issuer, issue_args, db_session, mocker):
    mocker.patch.object(
        type(issuer.signer), "sign", side_effect=RuntimeError("signing failed")
    )
    with (
        pytest.raises(RuntimeError, match="signing failed"),
        db_session.begin_nested(),
    ):
        issuer.issue(**issue_args)
    assert db_session.scalar(select(func.count()).select_from(IssuedJWT)) == 0


def test_rejects_token_that_expires_during_signing(
    issuer, issue_args, db_session, clock, monkeypatch
):
    clock.tick(timedelta(milliseconds=900))
    sign = issuer.signer.sign

    def delayed_sign(self, claims):
        token = sign(claims)
        clock.tick(timedelta(milliseconds=100))
        return token

    monkeypatch.setattr(type(issuer.signer), "sign", delayed_sign)
    with (
        pytest.raises(RuntimeError, match="JWT expired during signing"),
        db_session.begin_nested(),
    ):
        issuer.issue(**issue_args, lifetime=1)
    assert db_session.scalar(select(func.count()).select_from(IssuedJWT)) == 0
