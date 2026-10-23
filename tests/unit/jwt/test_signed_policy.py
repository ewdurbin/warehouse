# SPDX-License-Identifier: Apache-2.0

import base64
import types

from datetime import UTC, datetime
from uuid import UUID

import pytest

from pyramid import testing
from pyramid.authorization import Allow
from pyramid.request import Request, apply_request_extensions

from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory, RoleFactory
from tests.common.jwt import (
    API_AUDIENCE,
    OTHER_ID,
    PROJECT_ID,
    UPLOAD_AUDIENCE,
    USER_ID,
)
from warehouse.accounts import _oidc_claims, _oidc_publisher, _user
from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.config import RootFactory
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.packaging.models import LifecycleStatus
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import AuthenticationMethod, MultiSecurityPolicy


class TestSignedJWTPolicy:
    @pytest.fixture
    def user(self, db_session):
        return UserFactory(id=UUID(USER_ID), is_observer=True, clear_pwd="password")

    @pytest.fixture
    def project(self, user):
        return RoleFactory(
            user=user, project__id=UUID(PROJECT_ID), role_name="Owner"
        ).project

    @pytest.fixture
    def other_project(self, user):
        return RoleFactory(
            user=user, project__id=UUID(OTHER_ID), role_name="Owner"
        ).project

    @pytest.fixture
    def jwt_request(
        self, verifier, user, user_service, sign, jwt_registry, registered_jti
    ):
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service(verifier, IJWTVerifier)
            config.register_service(jwt_registry, IJWTRegistry)
            config.register_service(user_service, IUserService)
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/danger-api/echo")
            request.registry = config.registry
            apply_request_extensions(request)
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"jwt"}, None)]
            )
            request.headers["Authorization"] = f"Bearer {sign()}"
            yield request

    @pytest.mark.parametrize("is_observer", [True, False])
    def test_live_acl_is_required(self, jwt_request, user, is_observer):
        user.is_observer = is_observer
        assert jwt_request.identity == UserContext(user, macaroon=None)
        assert jwt_request.authentication_method == AuthenticationMethod.JWT
        result = jwt_request.has_permission(
            Permissions.APIEcho, RootFactory(jwt_request)
        )
        assert bool(result) == is_observer

    def test_rechecks_expiration(self, jwt_request, clock, claims):
        assert jwt_request.identity is not None
        clock.move_to(datetime.fromtimestamp(claims["exp"], UTC))
        result = jwt_request.has_permission(
            Permissions.APIEcho, RootFactory(jwt_request)
        )
        assert not result
        assert result.reason == "invalid_jwt"

    def test_overlong_token_does_not_authenticate(self, jwt_request, sign, claims):
        claims["exp"] = claims["iat"] + 301
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.identity is None
        assert not jwt_request.has_permission(
            Permissions.APIEcho, RootFactory(jwt_request)
        )

    @pytest.mark.parametrize("expected_audience", [UPLOAD_AUDIENCE, API_AUDIENCE])
    @pytest.mark.parametrize(
        "token_audience",
        [API_AUDIENCE, UPLOAD_AUDIENCE, [API_AUDIENCE, UPLOAD_AUDIENCE]],
    )
    def test_expected_audience_is_required(
        self, jwt_request, sign, claims, expected_audience, token_audience
    ):
        claims["aud"] = token_audience
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert (jwt_request.identity is not None) == (
            token_audience == expected_audience
        )

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    @pytest.mark.parametrize("granted", [False, True])
    def test_matching_audience_still_requires_permission(
        self, jwt_request, sign, claims, project, expected_audience, permission, granted
    ):
        claims["aud"] = expected_audience
        claims["authorization_details"] = [
            detail
            for detail in claims["authorization_details"]
            if (permission in detail["actions"]) == granted
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.identity is not None
        assert bool(jwt_request.has_permission(permission, project)) == granted

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    @pytest.mark.parametrize("scoped", [False, True])
    def test_project_scope_cannot_be_bypassed_by_acl(
        self, jwt_request, sign, claims, project, expected_audience, permission, scoped
    ):
        claims["aud"] = expected_audience
        for detail in claims["authorization_details"]:
            if "identifier" in detail:
                detail["identifier"] = f"project:{PROJECT_ID if scoped else OTHER_ID}"
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert bool(jwt_request.has_permission(permission, project)) == scoped

    def test_permission_resource_pairs_do_not_cross(
        self, jwt_request, claims, sign, project, other_project
    ):
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["projects:upload"],
                "identifier": f"project:{PROJECT_ID}",
            },
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{OTHER_ID}",
            },
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.has_permission(Permissions.ProjectsUpload, project)
        assert not jwt_request.has_permission(Permissions.APIObservationsAdd, project)
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, other_project)
        assert jwt_request.has_permission(Permissions.APIObservationsAdd, other_project)

    def test_multiple_actions_share_one_identifier(
        self, jwt_request, claims, sign, project, other_project
    ):
        permissions = [Permissions.ProjectsUpload, Permissions.APIObservationsAdd]
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": permissions,
                "identifier": f"project:{PROJECT_ID}",
            }
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        for permission in permissions:
            assert jwt_request.has_permission(permission, project)
        for permission in permissions:
            assert not jwt_request.has_permission(permission, other_project)

    def test_permission_wide_action_does_not_widen_other_details(
        self, jwt_request, claims, sign, project, other_project
    ):
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["projects:upload"]},
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{OTHER_ID}",
            },
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.has_permission(Permissions.ProjectsUpload, project)
        assert not jwt_request.has_permission(Permissions.APIObservationsAdd, project)
        assert jwt_request.has_permission(Permissions.ProjectsUpload, other_project)
        assert jwt_request.has_permission(Permissions.APIObservationsAdd, other_project)


class TestSignedPublisherJWTPolicy:
    @pytest.fixture(params=[True, False])
    def narrowed_upload(self, request):
        return request.param

    @pytest.fixture
    def expected_audience(self):
        return UPLOAD_AUDIENCE

    @pytest.fixture
    def publisher(self, db_session):
        return GitHubPublisherFactory()

    @pytest.fixture
    def publisher_project(self, publisher):
        return ProjectFactory(oidc_publishers=[publisher])

    @pytest.fixture
    def jwt_request(
        self,
        verifier,
        publisher,
        publisher_project,
        claims,
        sign,
        db_session,
        mocker,
        expected_audience,
        narrowed_upload,
        jwt_registry,
        registered_jti,
    ):
        upload_detail = {"type": "warehouse", "actions": ["projects:upload"]}
        if narrowed_upload:
            upload_detail["identifier"] = f"project:{publisher_project.id}"
        claims.update(
            sub=str(publisher.id),
            subject_kind="publisher",
            aud=expected_audience,
            authorization_details=[
                upload_detail,
                {"type": "warehouse", "actions": ["api:echo"]},
            ],
        )
        user_service = mocker.Mock(spec=["get_user", "is_disabled"])
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service(verifier, IJWTVerifier)
            config.register_service(jwt_registry, IJWTRegistry)
            config.register_service(user_service, IUserService)
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/")
            request.registry = config.registry
            apply_request_extensions(request)
            request.db = db_session
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"jwt"}, None)]
            )
            request.headers["Authorization"] = f"Bearer {sign()}"
            yield request
        user_service.get_user.assert_not_called()
        user_service.is_disabled.assert_not_called()

    def test_publisher_uses_existing_identity_contract(
        self, jwt_request, publisher, publisher_project
    ):
        assert jwt_request.identity == PublisherTokenContext(publisher, claims=None)
        assert jwt_request.authenticated_userid is None
        assert _user(jwt_request) is None
        assert _oidc_publisher(jwt_request) is publisher
        assert _oidc_claims(jwt_request) is None
        assert jwt_request.authentication_method == AuthenticationMethod.JWT
        assert jwt_request.has_permission(Permissions.ProjectsUpload, publisher_project)

    def test_removing_publisher_from_project_denies(
        self, jwt_request, publisher_project, db_session
    ):
        assert jwt_request.has_permission(Permissions.ProjectsUpload, publisher_project)
        publisher_project.oidc_publishers.clear()
        db_session.flush()
        db_session.expire(publisher_project, ["oidc_publishers"])
        assert not jwt_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

    def test_new_project_membership_respects_scope(
        self, jwt_request, publisher, narrowed_upload, db_session
    ):
        # Reuse the exact signed token and cached identity after membership changes.
        assert jwt_request.identity is not None
        original_header = jwt_request.headers["Authorization"]
        other = ProjectFactory()
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, other)
        other.oidc_publishers.append(publisher)
        db_session.flush()
        db_session.expire(other, ["oidc_publishers"])
        assert bool(jwt_request.has_permission(Permissions.ProjectsUpload, other)) == (
            not narrowed_upload
        )
        assert jwt_request.headers["Authorization"] == original_header

    def test_unrelated_project_denies(self, jwt_request):
        other = ProjectFactory(oidc_publishers=[GitHubPublisherFactory()])
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, other)

    def test_project_context_required_even_with_granting_acl(
        self, jwt_request, publisher, publisher_project
    ):
        context = types.SimpleNamespace(
            id=publisher_project.id,
            __acl__=[(Allow, f"oidc:{publisher.id}", Permissions.ProjectsUpload)],
        )
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, context)

    def test_upload_grant_does_not_allow_other_permissions(
        self, jwt_request, claims, sign, publisher_project
    ):
        claims["authorization_details"] = [claims["authorization_details"][0]]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        for permission, context in (
            (Permissions.APIEcho, RootFactory(jwt_request)),
            (Permissions.APIObservationsAdd, publisher_project),
        ):
            result = jwt_request.has_permission(permission, context)
            assert not result
            assert result.reason == "invalid_jwt"

    def test_wrong_audience_denies(self, jwt_request, claims, sign):
        claims["aud"] = API_AUDIENCE
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.identity is None

    def test_deleting_publisher_denies(self, jwt_request, publisher, db_session):
        db_session.delete(publisher)
        db_session.flush()
        assert jwt_request.identity is None

    @pytest.mark.parametrize(
        "status", [LifecycleStatus.Archived, LifecycleStatus.QuarantineEnter]
    )
    def test_project_status_still_applies(self, jwt_request, publisher_project, status):
        publisher_project.lifecycle_status = status
        assert not jwt_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

    def test_rechecks_expiration(self, jwt_request, publisher_project, clock, claims):
        assert jwt_request.identity is not None
        clock.move_to(datetime.fromtimestamp(claims["exp"], UTC))
        result = jwt_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )
        assert not result
        assert result.reason == "invalid_jwt"

    @pytest.mark.parametrize("expected_audience", [API_AUDIENCE])
    def test_publisher_subject_is_not_upload_specific(self, jwt_request, publisher):
        # This is an explicitly granting test ACL, not a change to the danger API.
        context = types.SimpleNamespace(
            __acl__=[(Allow, f"oidc:{publisher.id}", Permissions.APIEcho)]
        )
        assert jwt_request.has_permission(Permissions.APIEcho, context)

    @pytest.mark.parametrize("scheme", ["Basic", "Token"])
    def test_signed_publisher_jwt_is_bearer_only(self, jwt_request, sign, scheme):
        token = sign()
        if scheme == "Basic":
            token = base64.b64encode(f"__token__:{token}".encode()).decode()
        jwt_request.headers["Authorization"] = f"{scheme} {token}"
        assert jwt_request.identity is None

    @pytest.mark.parametrize("expected_audience", [API_AUDIENCE])
    def test_publisher_cannot_report_observations_even_with_permission_wide_grant(
        self, jwt_request, claims, sign, publisher_project
    ):
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert isinstance(jwt_request.identity, PublisherTokenContext)
        assert not jwt_request.has_permission(
            Permissions.APIObservationsAdd, publisher_project
        )
