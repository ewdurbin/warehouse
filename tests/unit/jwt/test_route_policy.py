# SPDX-License-Identifier: Apache-2.0


from datetime import UTC, datetime
from uuid import UUID

import pytest

from pyramid.authorization import Allow
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory, RoleFactory
from tests.common.jwt import (
    API_AUDIENCE,
    NOW,
    OTHER_ID,
    UPLOAD_AUDIENCE,
    USER_ID,
)
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTVerifier,
)
from warehouse.utils.security_policy import AuthenticationMethod


class TestAudienceJWTService:
    @pytest.mark.parametrize(
        ("path", "route_name", "audience", "permission"),
        [
            (
                "/legacy/?:action=file_upload",
                "forklift.legacy.file_upload",
                UPLOAD_AUDIENCE,
                Permissions.ProjectsUpload,
            ),
            ("/danger-api/echo", "api.echo", API_AUDIENCE, Permissions.APIEcho),
            (
                "/danger-api/projects/example/observations",
                "api.projects.observations",
                API_AUDIENCE,
                Permissions.APIObservationsAdd,
            ),
        ],
    )
    @pytest.mark.parametrize(
        "token_audience",
        [API_AUDIENCE, UPLOAD_AUDIENCE, [API_AUDIENCE, UPLOAD_AUDIENCE]],
    )
    @pytest.mark.parametrize("kid", ["current", "previous"])
    def test_audience_binding(
        self,
        make_request,
        sign,
        claims,
        headers,
        signing_keys,
        user,
        project,
        path,
        route_name,
        audience,
        permission,
        token_audience,
        kid,
    ):
        claims["aud"] = token_audience
        headers["kid"] = kid
        token = sign(key=signing_keys[0 if kid == "current" else 1])
        request = make_request(path, token)
        assert request.matched_route.name == route_name
        project.__acl__ = [(Allow, f"user:{USER_ID}", permission)]
        accepted = token_audience == audience
        assert request.identity == (
            UserContext(user, macaroon=None) if accepted else None
        )
        assert bool(request.has_permission(permission, project)) == accepted
        if accepted:
            assert request.authentication_method == AuthenticationMethod.JWT

    @pytest.mark.parametrize("jwt_enabled", [None, False, "false"])
    def test_disabled_by_default(self, make_request, sign):
        # Having valid keys alone must not enable JWTs.
        request = make_request("/danger-api/echo", sign())
        assert isinstance(
            request.find_service(IJWTVerifier, context=None), DisabledJWTVerifier
        )
        assert request.identity is None

    @pytest.mark.parametrize(
        ("audience_name", "audience"),
        [("api", API_AUDIENCE), ("upload", UPLOAD_AUDIENCE)],
    )
    @pytest.mark.parametrize("token_audience", [API_AUDIENCE, UPLOAD_AUDIENCE])
    def test_new_routes_need_no_verifier_changes(
        self, make_request, sign, claims, audience_name, audience, token_audience
    ):
        claims["aud"] = token_audience
        request = make_request(f"/audience-test/{audience_name}", sign())
        assert request.matched_route.name == f"new-endpoint.{audience_name}"
        assert (request.identity is not None) == (token_audience == audience)

    def test_audiences_do_not_change_each_others_verifier(
        self, make_request, sign, claims, project
    ):
        api_request = make_request("/danger-api/echo", sign())
        claims["aud"] = UPLOAD_AUDIENCE
        upload_request = make_request("/legacy/?:action=file_upload", sign())
        assert api_request.identity is not None
        assert upload_request.identity is not None
        project.__acl__ = [
            (
                Allow,
                f"user:{USER_ID}",
                [Permissions.APIEcho, Permissions.ProjectsUpload],
            )
        ]
        assert api_request.has_permission(Permissions.APIEcho, project)
        assert upload_request.has_permission(Permissions.ProjectsUpload, project)
        assert api_request.has_permission(Permissions.APIEcho, project)

    @pytest.mark.parametrize(
        "matched_path", ["/danger-api/echo", "/legacy/?:action=file_upload"]
    )
    def test_untrusted_request_fields_cannot_choose_audience(
        self, make_request, sign, claims, matched_path
    ):
        claims["aud"] = (
            UPLOAD_AUDIENCE if matched_path.startswith("/danger-api") else API_AUDIENCE
        )
        request = make_request(matched_path, sign())
        # Once routing is resolved, even hostile request metadata cannot select
        # the other verifier. Real routing is tested separately above.
        request.host = "attacker.example"
        request.path_info = (
            "/legacy/" if matched_path.startswith("/danger-api") else "/danger-api/echo"
        )
        request.query_string = f"aud={claims['aud']}&jwt_audience=api"
        request.headers["X-Forwarded-Host"] = "attacker.example"
        request.headers["X-JWT-Audience"] = claims["aud"]
        assert request.identity is None


class TestRegisteredJWTPolicy:
    @pytest.fixture
    def user(self, db_session):
        return UserFactory()

    @pytest.fixture(params=["user", "publisher"])
    def subject_kind(self, request):
        return request.param

    @pytest.fixture
    def subject(self, subject_kind, user):
        return user if subject_kind == "user" else GitHubPublisherFactory()

    @pytest.fixture(autouse=True)
    def upload_claims(self, claims, subject, subject_kind):
        claims.update(
            sub=str(subject.id),
            subject_kind=subject_kind,
            aud=UPLOAD_AUDIENCE,
            authorization_details=[
                {"type": "warehouse", "actions": ["projects:upload"]}
            ],
        )

    @pytest.fixture
    def project(self, subject, subject_kind):
        if subject_kind == "publisher":
            return ProjectFactory(oidc_publishers=[subject])
        project = ProjectFactory()
        RoleFactory(project=project, user=subject, role_name="Owner")
        return project

    def test_rechecks_credential_and_registry_for_each_operation(
        self, make_request, sign, project, registered_jti, mocker
    ):
        token = sign()
        request = make_request("/legacy/?:action=file_upload", token)
        registry = request.find_service(IJWTRegistry, context=None)
        active_check = mocker.spy(registry, "is_active")
        entry_check = mocker.spy(registry, "get_active")
        verifier = request.find_service(IJWTVerifier, context=None)
        verify = mocker.spy(verifier, "verify")

        assert request.identity is not None
        assert request.authentication_method == AuthenticationMethod.JWT
        assert request.has_permission(Permissions.ProjectsUpload, project)
        assert not request.has_permission(Permissions.ProjectsUpload, ProjectFactory())
        assert not request.has_permission(Permissions.APIObservationsAdd, project)
        assert not request.has_permission(Permissions.AccountManage, project)
        assert request.has_permission(Permissions.ProjectsUpload, project)
        # Authentication plus four JWT permission checks; AccountManage is
        # denied by the method allowlist without needing credential validation.
        entry_check.assert_called_once_with(registered_jti)
        assert active_check.call_args_list == [mocker.call(registered_jti)] * 4
        assert verify.call_args_list == [mocker.call(token)] * 5

    @pytest.mark.parametrize("state", ["missing", "expired", "revoked"])
    def test_inactive_registry_entry_cannot_authenticate(
        self,
        make_request,
        sign,
        claims,
        project,
        jwt_registry,
        registered_jti,
        db_session,
        state,
        mocker,
    ):
        if state == "missing":
            # Another active registry entry cannot authorize this JTI.
            claims["jti"] = OTHER_ID
        elif state == "expired":
            db_session.get(IssuedJWT, registered_jti).expires_at = datetime.now(UTC)
        else:
            jwt_registry.revoke(registered_jti)

        request = make_request("/legacy/?:action=file_upload", sign())
        registry = request.find_service(IJWTRegistry, context=None)
        active_check = mocker.spy(registry, "get_active")
        assert request.identity is None
        assert not request.has_permission(Permissions.ProjectsUpload, project)
        assert not hasattr(request, "authentication_method")
        active_check.assert_called_once_with(UUID(claims["jti"]))

    @pytest.mark.parametrize("authenticated", [False, True])
    def test_database_error_does_not_allow_access(
        self, make_request, sign, project, db_session, mocker, authenticated
    ):
        request = make_request("/legacy/?:action=file_upload", sign())
        if authenticated:
            assert request.identity is not None
        mocker.patch.object(
            db_session,
            "scalar",
            side_effect=OperationalError(
                "statement", {}, Exception("database unavailable")
            ),
        )
        with pytest.raises(OperationalError):
            request.has_permission(Permissions.ProjectsUpload, project)
        assert hasattr(request, "authentication_method") == authenticated

    def test_invalid_signature_does_not_query_registry(
        self, make_request, sign, signing_keys, mocker
    ):
        request = make_request(
            "/legacy/?:action=file_upload", sign(key=signing_keys[1])
        )
        registry = request.find_service(IJWTRegistry, context=None)
        entry_check = mocker.spy(registry, "get_active")
        active_check = mocker.spy(registry, "is_active")
        assert request.identity is None
        entry_check.assert_not_called()
        active_check.assert_not_called()

    @pytest.mark.parametrize("expiration", ["token", "registry"])
    def test_expiration_denies_authorization_with_cached_identity(
        self,
        make_request,
        sign,
        claims,
        project,
        registered_jti,
        db_session,
        clock,
        expiration,
        mocker,
    ):
        expires_at = datetime.fromtimestamp(
            NOW + 1 if expiration == "registry" else claims["exp"], UTC
        )
        if expiration == "registry":
            db_session.get(IssuedJWT, registered_jti).expires_at = expires_at
        token = sign()
        request = make_request("/legacy/?:action=file_upload", token)
        active_check = mocker.spy(
            request.find_service(IJWTRegistry, context=None), "is_active"
        )
        assert request.identity is not None

        clock.move_to(expires_at)
        result = request.has_permission(Permissions.ProjectsUpload, project)
        assert not result
        assert result.reason == "invalid_api_key"
        # Expired JWTs fail verification before consulting the registry again.
        assert active_check.call_args_list == [mocker.call(registered_jti)] * (
            1 if expiration == "registry" else 0
        )

        fresh_request = make_request("/legacy/?:action=file_upload", token)
        assert fresh_request.identity is None
        assert not fresh_request.has_permission(Permissions.ProjectsUpload, project)

    @pytest.mark.parametrize("already_authorized", [False, True])
    def test_committed_revocation_denies_authorization_with_cached_identity(
        self,
        make_request,
        sign,
        claims,
        project,
        app_config,
        mocker,
        already_authorized,
    ):
        # The request's DB transaction remains open while another one revokes.
        with Session(app_config.registry["sqlalchemy.engine"]) as writer:
            issuer = DatabaseJWTRegistry(writer)
            token_id = issuer.register(datetime.fromtimestamp(claims["exp"], UTC))
            writer.commit()
            try:
                claims["jti"] = str(token_id)
                token = sign()
                request = make_request("/legacy/?:action=file_upload", token)
                active_check = mocker.spy(
                    request.find_service(IJWTRegistry, context=None), "is_active"
                )
                assert request.identity is not None
                if already_authorized:
                    assert request.has_permission(Permissions.ProjectsUpload, project)

                issuer.revoke(token_id)
                writer.commit()
                result = request.has_permission(Permissions.ProjectsUpload, project)
                assert not result
                assert result.reason == "invalid_api_key"
                assert active_check.call_args_list == [mocker.call(token_id)] * (
                    2 if already_authorized else 1
                )

                fresh_request = make_request("/legacy/?:action=file_upload", token)
                assert fresh_request.identity is None
                assert not fresh_request.has_permission(
                    Permissions.ProjectsUpload, project
                )
            finally:
                issuer.revoke(token_id)
                writer.commit()


class TestSignedObservationJWTPolicy:
    @pytest.fixture
    def user(self, db_session):
        return UserFactory(is_observer=True)

    @pytest.fixture(autouse=True)
    def observation_claims(self, claims, user):
        claims["sub"] = str(user.id)
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]

    def test_observer_can_report_on_unrelated_projects(self, make_request, sign, user):
        projects = [ProjectFactory(), ProjectFactory()]
        token = sign()
        for project in projects:
            request = make_request(
                f"/danger-api/projects/{project.name}/observations", token
            )
            assert request.matched_route.name == "api.projects.observations"
            assert request.identity == UserContext(user, macaroon=None)
            assert request.authentication_method == AuthenticationMethod.JWT
            assert request.has_permission(Permissions.APIObservationsAdd, project)

    @pytest.mark.parametrize("narrowed", [False, True])
    @pytest.mark.parametrize("role_name", [None, "Owner", "Maintainer"])
    def test_nonobserver_cannot_report(
        self, make_request, sign, claims, user, narrowed, role_name
    ):
        user.is_observer = False
        project = ProjectFactory()
        if role_name is not None:
            RoleFactory(user=user, project=project, role_name=role_name)
        if narrowed:
            claims["authorization_details"] = [
                {
                    "type": "warehouse",
                    "actions": ["api:observations:add"],
                    "identifier": f"project:{project.id}",
                }
            ]
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.identity == UserContext(user, macaroon=None)
        assert not request.has_permission(Permissions.APIObservationsAdd, project)

    def test_observer_privilege_removal_takes_effect(
        self, make_request, sign, user, db_session
    ):
        project = ProjectFactory()
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.has_permission(Permissions.APIObservationsAdd, project)
        user.is_observer = False
        db_session.flush()
        db_session.expire(user, ["is_observer"])
        assert not request.has_permission(Permissions.APIObservationsAdd, project)

    def test_resource_narrowing(self, make_request, sign, claims):
        allowed, other = ProjectFactory(), ProjectFactory()
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{allowed.id}",
            }
        ]
        token = sign()
        request = make_request(
            f"/danger-api/projects/{allowed.name}/observations", token
        )
        assert request.has_permission(Permissions.APIObservationsAdd, allowed)
        request = make_request(f"/danger-api/projects/{other.name}/observations", token)
        assert request.identity is not None
        assert not request.has_permission(Permissions.APIObservationsAdd, other)

    @pytest.mark.parametrize("include_broad", [False, True])
    def test_details_are_additive(self, make_request, sign, claims, include_broad):
        first, second, other = ProjectFactory(), ProjectFactory(), ProjectFactory()
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{project.id}",
            }
            for project in (first, second)
        ]
        if include_broad:
            claims["authorization_details"].append(
                {"type": "warehouse", "actions": ["api:observations:add"]}
            )
        token = sign()
        for project in (first, second, other):
            request = make_request(
                f"/danger-api/projects/{project.name}/observations", token
            )
            assert bool(
                request.has_permission(Permissions.APIObservationsAdd, project)
            ) == (include_broad or project in (first, second))

    def test_grant_does_not_allow_other_operations(self, make_request, sign):
        project = ProjectFactory()
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.has_permission(Permissions.APIObservationsAdd, project)
        assert not request.has_permission(Permissions.APIEcho, project)
        assert not request.has_permission(Permissions.ProjectsUpload, project)

    def test_observer_privilege_does_not_replace_grant(
        self, make_request, sign, claims
    ):
        project = ProjectFactory()
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:echo"]}
        ]
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.identity is not None
        assert not request.has_permission(Permissions.APIObservationsAdd, project)
