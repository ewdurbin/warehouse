# SPDX-License-Identifier: Apache-2.0

import base64

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from pyramid import testing
from pyramid.request import Request, apply_request_extensions
from sqlalchemy.exc import OperationalError

from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from tests.common.jwt import API_AUDIENCE, UPLOAD_AUDIENCE, USER_ID
from warehouse.accounts import _oidc_claims, _oidc_publisher, _user
from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.config import RootFactory
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import AuthenticationMethod, MultiSecurityPolicy

OIDC_CLAIMS = {"sha": "a" * 40}


@pytest.fixture
def jwt_request(verifier, jwt_registry, user_service, db_session):
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
        request.matched_route = SimpleNamespace(
            predicates=[AuthMethodsPredicate({"jwt"}, None)]
        )
        yield request


class TestSignedUserJWTPolicy:
    @pytest.fixture
    def user(self, db_session):
        return UserFactory(id=UUID(USER_ID), is_observer=True, clear_pwd="password")

    @pytest.fixture
    def user_request(self, jwt_request, user, sign, registered_jti):
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        return jwt_request

    @pytest.mark.parametrize("is_observer", [True, False])
    def test_observations_require_observer(
        self, user_request, user, claims, sign, is_observer
    ):
        user.is_observer = is_observer
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]
        user_request.headers["Authorization"] = f"Bearer {sign()}"

        assert user_request.identity == UserContext(user, macaroon=None)
        assert user_request.authenticated_userid == str(user.id)
        assert user_request.authentication_method == AuthenticationMethod.JWT
        result = user_request.has_permission(
            Permissions.APIObservationsAdd, ProjectFactory()
        )
        assert bool(result) == is_observer

    def test_acl_cannot_allow_a_missing_token_grant(self, user_request, claims, sign):
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]
        user_request.headers["Authorization"] = f"Bearer {sign()}"

        result = user_request.has_permission(
            Permissions.APIEcho, RootFactory(user_request)
        )
        assert not result
        assert result.reason == "invalid_jwt"

    def test_frozen_user_does_not_authenticate(self, user_request, user):
        user.is_frozen = True

        assert user_request.identity is None

    def test_user_subject_does_not_resolve_as_publisher(
        self, user_request, claims, sign
    ):
        publisher = GitHubPublisherFactory()
        token = sign({**claims, "sub": str(publisher.id)})
        user_request.headers["Authorization"] = f"Bearer {token}"

        assert user_request.identity is None

    @pytest.mark.parametrize(
        "route",
        [
            pytest.param(None, id="no-route"),
            pytest.param(SimpleNamespace(predicates=[]), id="untagged"),
            pytest.param(
                SimpleNamespace(predicates=[AuthMethodsPredicate({"api-key"}, None)]),
                id="api-key",
            ),
        ],
    )
    def test_route_must_opt_in_to_jwt(self, user_request, route):
        user_request.matched_route = route

        assert user_request.identity is None

    def test_missing_registry_entry_does_not_authenticate(
        self, user_request, jwt_registry, registered_jti
    ):
        jwt_registry.revoke(registered_jti)

        assert user_request.identity is None

    def test_authorizes_the_original_credential(self, user_request):
        assert user_request.identity is not None
        user_request.headers["Authorization"] = "Bearer invalid"

        assert user_request.has_permission(
            Permissions.APIEcho, RootFactory(user_request)
        )

    def test_rechecks_token_expiration_while_registry_entry_is_active(
        self, user_request, clock, claims, sign, jwt_registry, registered_jti
    ):
        expires_at = claims["exp"] - 1
        token = sign({**claims, "exp": expires_at})
        user_request.headers["Authorization"] = f"Bearer {token}"
        context = RootFactory(user_request)
        assert user_request.has_permission(Permissions.APIEcho, context)

        clock.move_to(datetime.fromtimestamp(expires_at, UTC))

        assert jwt_registry.is_active(registered_jti)
        result = user_request.has_permission(Permissions.APIEcho, context)
        assert not result
        assert result.reason == "invalid_jwt"

    def test_rechecks_revocation_while_token_still_verifies(
        self, user_request, verifier, jwt_registry, registered_jti
    ):
        context = RootFactory(user_request)
        assert user_request.has_permission(Permissions.APIEcho, context)
        identity = user_request.identity
        token = user_request.headers["Authorization"].removeprefix("Bearer ")

        jwt_registry.revoke(registered_jti)

        assert user_request.identity is identity
        assert verifier.verify(token) is not None
        result = user_request.has_permission(Permissions.APIEcho, context)
        assert not result
        assert result.reason == "invalid_jwt"

    def test_registry_failure_during_authorization_propagates(
        self, user_request, jwt_registry, mocker
    ):
        context = RootFactory(user_request)
        assert user_request.has_permission(Permissions.APIEcho, context)
        mocker.patch.object(
            jwt_registry,
            "is_active",
            side_effect=OperationalError(
                "statement", {}, Exception("registry unavailable")
            ),
        )

        with pytest.raises(OperationalError, match="registry unavailable"):
            user_request.has_permission(Permissions.APIEcho, context)


class TestSignedPublisherJWTPolicy:
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
    def publisher_request(
        self, jwt_request, publisher, claims, sign, jwt_registry, expected_audience
    ):
        token_id = jwt_registry.register(
            datetime.fromtimestamp(claims["exp"], UTC),
            additional={"oidc": OIDC_CLAIMS},
        )
        claims.update(
            sub=str(publisher.id),
            subject_kind="publisher",
            jti=str(token_id),
            aud=expected_audience,
            authorization_details=[
                {"type": "warehouse", "actions": ["projects:upload"]}
            ],
        )
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        return jwt_request

    def test_publisher_identity_includes_stored_claims(
        self, publisher_request, publisher, publisher_project
    ):
        assert publisher_request.identity == PublisherTokenContext(
            publisher, claims=OIDC_CLAIMS
        )
        assert publisher_request.authenticated_userid is None
        assert _user(publisher_request) is None
        assert _oidc_publisher(publisher_request) is publisher
        assert _oidc_claims(publisher_request) == OIDC_CLAIMS
        assert publisher_request.authentication_method == AuthenticationMethod.JWT
        assert publisher_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

    @pytest.mark.parametrize("scheme", ["Basic", "Token"])
    def test_publisher_jwt_requires_bearer(self, publisher_request, scheme):
        token = publisher_request.headers["Authorization"].removeprefix("Bearer ")
        if scheme == "Basic":
            token = base64.b64encode(f"__token__:{token}".encode()).decode()
        publisher_request.headers["Authorization"] = f"{scheme} {token}"

        assert publisher_request.identity is None

    def test_deleting_publisher_denies(self, publisher_request, publisher, db_session):
        db_session.delete(publisher)
        db_session.flush()

        assert publisher_request.identity is None

    def test_removing_publisher_from_project_denies(
        self, publisher_request, publisher_project, db_session
    ):
        assert publisher_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

        publisher_project.oidc_publishers.clear()
        db_session.flush()
        db_session.expire(publisher_project, ["oidc_publishers"])

        assert not publisher_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

    @pytest.mark.parametrize(
        "narrowed", [True, False], ids=["project-scoped", "permission-wide"]
    )
    def test_new_project_membership_respects_scope(
        self,
        publisher_request,
        publisher,
        publisher_project,
        claims,
        sign,
        db_session,
        narrowed,
    ):
        if narrowed:
            claims["authorization_details"][0]["identifier"] = (
                f"project:{publisher_project.id}"
            )
            publisher_request.headers["Authorization"] = f"Bearer {sign()}"

        assert publisher_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )
        other = ProjectFactory()
        assert not publisher_request.has_permission(Permissions.ProjectsUpload, other)

        other.oidc_publishers.append(publisher)
        db_session.flush()
        db_session.expire(other, ["oidc_publishers"])

        result = publisher_request.has_permission(Permissions.ProjectsUpload, other)
        assert bool(result) == (not narrowed)

    @pytest.mark.parametrize("expected_audience", [API_AUDIENCE])
    def test_observations_deny_publisher_even_with_grant(
        self, publisher_request, publisher_project, claims, sign
    ):
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]
        publisher_request.headers["Authorization"] = f"Bearer {sign()}"

        assert isinstance(publisher_request.identity, PublisherTokenContext)
        assert not publisher_request.has_permission(
            Permissions.APIObservationsAdd, publisher_project
        )
