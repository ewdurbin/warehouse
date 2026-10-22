# SPDX-License-Identifier: Apache-2.0

import types

from dataclasses import replace

import pytest

from pyramid import testing
from pyramid.authorization import Allow, Authenticated
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import Request, apply_request_extensions
from pyramid.response import Response
from zope.interface.verify import verifyClass

from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.claims import SubjectKind, SubjectRef
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.security_policy import JWTSecurityPolicy, _extract_http_jwt
from warehouse.oidc.models import OIDCPublisher
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import AuthenticationMethod, MultiSecurityPolicy

TOKEN = "header.payload.signature"


@pytest.fixture
def verifier(mocker):
    service = mocker.Mock(spec=["verify"])
    service.verify.return_value = None
    return service


@pytest.fixture
def registry(mocker):
    service = mocker.Mock(spec=["get_active", "is_active"])
    service.get_active.return_value = types.SimpleNamespace(additional={})
    service.is_active.return_value = True
    return service


@pytest.fixture(autouse=True)
def grant_check(mocker):
    return mocker.patch(
        "warehouse.jwt.security_policy.authorization.permits", return_value=False
    )


@pytest.fixture
def user():
    return types.SimpleNamespace(
        id="ddf9597e-dda1-45a2-b026-3a090ad7c4b2",
        __principals__=lambda: [Authenticated, "user:test"],
    )


@pytest.fixture
def user_service(mocker, user):
    service = mocker.Mock(spec=["get_user", "is_disabled"])
    service.get_user.return_value = user
    service.is_disabled.return_value = (False, None)
    return service


@pytest.fixture
def policy():
    return JWTSecurityPolicy()


@pytest.fixture
def jwt_request(policy, verifier, registry, user_service):
    with testing.testConfig() as config:
        config.include("pyramid_services")
        config.register_service(verifier, IJWTVerifier)
        config.register_service(registry, IJWTRegistry)
        config.register_service(user_service, IUserService)
        config.set_security_policy(MultiSecurityPolicy([policy]))
        config.commit()
        request = Request.blank("/danger-api/echo")
        request.registry = config.registry
        apply_request_extensions(request)
        request.matched_route = types.SimpleNamespace(
            name="api.echo", predicates=[AuthMethodsPredicate({"api-key"}, None)]
        )
        request.headers["Authorization"] = f"Bearer {TOKEN}"
        yield request


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("Bearer", None),
        ("Bearer   ", None),
        ("Bearer one two", None),
        (f"Basic {TOKEN}", None),
        (f"Token {TOKEN}", None),
        ("Basic X190b2tlbl9fOnB5cGktdG9rZW4=", None),
        ("Bearer pypi-token", None),
        (f"Bearer {TOKEN}", TOKEN),
        (f"bEaReR {TOKEN}", TOKEN),
        (f"Bearer   {TOKEN}", TOKEN),
        # Extraction does not establish JWT validity; the verifier must do that.
        ("Bearer garbage", "garbage"),
    ],
)
def test_extract_http_jwt(header, expected):
    request = Request.blank("/")
    if header is not None:
        request.headers["Authorization"] = header
    assert _extract_http_jwt(request) == expected


class TestJWTSecurityPolicy:
    def test_security_policy_interface(self):
        assert verifyClass(ISecurityPolicy, JWTSecurityPolicy)

    def test_header_authentication_lifecycle(self, policy, jwt_request):
        assert policy.remember(jwt_request, "user-id") == []
        assert policy.forget(jwt_request) == []
        with pytest.raises(NotImplementedError):
            policy.authenticated_userid(jwt_request)

    @pytest.mark.parametrize("methods", [None, set(), {"session"}, {"macaroon"}])
    def test_explicit_route_opt_in(self, methods, jwt_request, verifier):
        jwt_request.matched_route.predicates = (
            [] if methods is None else [AuthMethodsPredicate(methods, None)]
        )
        assert jwt_request.identity is None
        verifier.verify.assert_not_called()

    def test_no_matched_route(self, jwt_request, verifier):
        jwt_request.matched_route = None
        assert jwt_request.identity is None
        verifier.verify.assert_not_called()

    @pytest.mark.parametrize("header", ["", "Basic credentials", "Bearer pypi-token"])
    def test_other_credentials(self, header, jwt_request, verifier):
        jwt_request.headers["Authorization"] = header
        assert jwt_request.identity is None
        verifier.verify.assert_not_called()

    def test_invalid_token(self, jwt_request, verifier, registry, user_service):
        assert jwt_request.identity is None
        verifier.verify.assert_called_once_with(TOKEN)
        registry.get_active.assert_not_called()
        registry.is_active.assert_not_called()
        user_service.get_user.assert_not_called()
        assert not hasattr(jwt_request, "authentication_method")

    def test_deleted_user(self, verified, jwt_request, verifier, user_service, user):
        verifier.verify.return_value = verified
        user_service.get_user.return_value = None
        assert jwt_request.identity is None
        user_service.get_user.assert_called_once_with(user.id)
        user_service.is_disabled.assert_not_called()

    def test_disabled_user(self, verified, jwt_request, verifier, user_service, user):
        verifier.verify.return_value = verified
        user_service.is_disabled.return_value = (True, "disabled")
        assert jwt_request.identity is None
        user_service.is_disabled.assert_called_once_with(user.id)

    def test_verified_user(
        self, verified, jwt_request, verifier, registry, user_service, user
    ):
        verifier.verify.return_value = verified
        assert jwt_request.identity == UserContext(user, macaroon=None)
        assert jwt_request.authenticated_userid == user.id
        assert jwt_request.authentication_method == AuthenticationMethod.API_KEY
        verifier.verify.assert_called_once_with(TOKEN)
        registry.get_active.assert_called_once_with(verified.jti)
        user_service.get_user.assert_called_once_with(user.id)
        user_service.is_disabled.assert_called_once_with(user.id)

    def test_varies_on_authorization(self, jwt_request):
        assert jwt_request.identity is None
        response = Response()
        response.vary = ("Accept",)
        jwt_request._process_response_callbacks(response)
        assert set(response.vary) == {"Accept", "Authorization"}

    @pytest.mark.parametrize(
        "permission", [Permissions.AccountManage, Permissions.AdminUsersRead, "unknown"]
    )
    def test_denies_non_api_key_permissions(
        self,
        grant_check,
        verified,
        permission,
        jwt_request,
        verifier,
        user,
        policy,
        mocker,
    ):
        verifier.verify.return_value = verified
        grant_check.return_value = True
        acl = mocker.spy(policy._acl, "permits")
        result = jwt_request.has_permission(permission, types.SimpleNamespace())
        assert not result
        assert result.reason == "invalid_permission"
        grant_check.assert_not_called()
        acl.assert_not_called()

    def test_denies_token_restrictions(
        self, grant_check, verified, jwt_request, verifier, user, policy, mocker
    ):
        verifier.verify.return_value = verified
        acl = mocker.spy(policy._acl, "permits")
        context = types.SimpleNamespace()
        result = jwt_request.has_permission(Permissions.APIEcho, context)
        assert not result
        assert result.reason == "invalid_api_key"
        grant_check.assert_called_once_with(
            verified, jwt_request.identity, context, Permissions.APIEcho
        )
        acl.assert_not_called()

    @pytest.mark.parametrize(
        "permission",
        [
            Permissions.ProjectsUpload,
            Permissions.APIEcho,
            Permissions.APIObservationsAdd,
        ],
    )
    @pytest.mark.parametrize("principal", ["user:test", "user:someone-else"])
    def test_requires_acl_and_token_permission(
        self, grant_check, verified, permission, principal, jwt_request, verifier, user
    ):
        verifier.verify.return_value = verified
        grant_check.return_value = True
        context = types.SimpleNamespace(__acl__=[(Allow, principal, permission)])
        assert bool(jwt_request.has_permission(permission, context)) == (
            principal == "user:test"
        )

    def test_authorizes_the_original_credential(
        self, grant_check, verified, jwt_request, verifier, registry, user, mocker
    ):
        verifier.verify.return_value = verified
        grant_check.return_value = True
        assert jwt_request.identity == UserContext(user, macaroon=None)
        jwt_request.headers["Authorization"] = "Bearer different.token.signature"
        context = types.SimpleNamespace(
            __acl__=[(Allow, "user:test", Permissions.APIEcho)]
        )
        assert jwt_request.has_permission(Permissions.APIEcho, context)
        assert verifier.verify.call_args_list == [mocker.call(TOKEN)] * 2
        registry.get_active.assert_called_once_with(verified.jti)
        registry.is_active.assert_called_once_with(verified.jti)
        grant_check.assert_called_once_with(
            verified, jwt_request.identity, context, Permissions.APIEcho
        )

    def test_verifier_error_does_not_authenticate(self, jwt_request, verifier):
        verifier.verify.side_effect = RuntimeError("verifier unavailable")
        with pytest.raises(RuntimeError, match="verifier unavailable"):
            _ = jwt_request.identity

    def test_authorization_error_does_not_allow(
        self, grant_check, verified, jwt_request, verifier, user
    ):
        verifier.verify.return_value = verified
        grant_check.side_effect = RuntimeError("verifier unavailable")
        with pytest.raises(RuntimeError, match="verifier unavailable"):
            jwt_request.has_permission(Permissions.APIEcho, types.SimpleNamespace())

    def test_existing_policy_wins(self, jwt_request, verifier, user, policy):
        identity = UserContext(user, macaroon=None)
        existing = testing.DummySecurityPolicy(identity=identity, permissive=False)
        combined = MultiSecurityPolicy([existing, policy])
        jwt_request.registry.registerUtility(combined, ISecurityPolicy)
        assert jwt_request.identity is identity
        assert not jwt_request.has_permission(
            Permissions.APIEcho, types.SimpleNamespace()
        )
        verifier.verify.assert_not_called()

    @pytest.mark.parametrize("kind", ["organization", "project", None])
    def test_unsupported_subject(
        self, jwt_request, verifier, verified, user_service, kind, mocker
    ):
        jwt_request.db = mocker.Mock()
        verifier.verify.return_value = replace(
            verified, subject=SubjectRef(kind, verified.subject.id)
        )
        assert jwt_request.identity is None
        user_service.get_user.assert_not_called()
        jwt_request.db.get.assert_not_called()
        assert not hasattr(jwt_request, "authentication_method")

    def test_missing_user_never_resolves_as_publisher(
        self, jwt_request, verifier, verified, user_service, mocker
    ):
        verifier.verify.return_value = verified
        user_service.get_user.return_value = None
        jwt_request.db = mocker.Mock()
        assert jwt_request.identity is None
        jwt_request.db.get.assert_not_called()

    @pytest.mark.parametrize("exists", [False, True])
    @pytest.mark.parametrize("additional", [{}, {"oidc": {}}, {"oidc": {"sha": "abc"}}])
    def test_publisher_identity(
        self,
        jwt_request,
        verifier,
        verified,
        registry,
        user_service,
        mocker,
        exists,
        additional,
    ):
        subject = SubjectRef(SubjectKind.PUBLISHER, verified.subject.id)
        verifier.verify.return_value = replace(verified, subject=subject)
        publisher = types.SimpleNamespace(id=subject.id) if exists else None
        jwt_request.db = mocker.Mock()
        jwt_request.db.get.return_value = publisher
        registry.get_active.return_value.additional = additional

        assert jwt_request.identity == (
            PublisherTokenContext(publisher, claims=additional.get("oidc"))
            if exists
            else None
        )
        assert jwt_request.authenticated_userid is None
        jwt_request.db.get.assert_called_once_with(OIDCPublisher, subject.id)
        user_service.get_user.assert_not_called()
        user_service.is_disabled.assert_not_called()
        if exists:
            assert jwt_request.authentication_method == AuthenticationMethod.API_KEY
            assert jwt_request.identity.__principals__() == [
                Authenticated,
                f"oidc:{subject.id}",
            ]
        else:
            assert not hasattr(jwt_request, "authentication_method")

    def test_publisher_lookup_failure_propagates(
        self, jwt_request, verifier, verified, mocker
    ):
        verifier.verify.return_value = replace(
            verified, subject=SubjectRef(SubjectKind.PUBLISHER, verified.subject.id)
        )
        jwt_request.db = mocker.Mock()
        jwt_request.db.get.side_effect = RuntimeError("database unavailable")
        with pytest.raises(RuntimeError, match="database unavailable"):
            _ = jwt_request.identity

    @pytest.mark.parametrize("subject_kind", [SubjectKind.USER, SubjectKind.PUBLISHER])
    def test_inactive_registry_entry_does_not_authenticate(
        self,
        jwt_request,
        verifier,
        verified,
        registry,
        user_service,
        subject_kind,
        mocker,
    ):
        verifier.verify.return_value = replace(
            verified, subject=SubjectRef(subject_kind, verified.subject.id)
        )
        registry.get_active.return_value = None
        jwt_request.db = mocker.Mock()
        assert jwt_request.identity is None
        registry.get_active.assert_called_once_with(verified.jti)
        user_service.get_user.assert_not_called()
        jwt_request.db.get.assert_not_called()
        assert not hasattr(jwt_request, "authentication_method")

    def test_registry_error_propagates(
        self, jwt_request, verifier, verified, registry, user_service
    ):
        verifier.verify.return_value = verified
        registry.get_active.side_effect = RuntimeError("registry unavailable")
        with pytest.raises(RuntimeError, match="registry unavailable"):
            jwt_request.has_permission(Permissions.APIEcho, types.SimpleNamespace())
        user_service.get_user.assert_not_called()
        assert not hasattr(jwt_request, "authentication_method")

    def test_reverification_failure_denies(
        self, jwt_request, verifier, verified, registry, grant_check, policy, mocker
    ):
        verifier.verify.side_effect = [verified, None]
        acl = mocker.spy(policy._acl, "permits")
        result = jwt_request.has_permission(
            Permissions.APIEcho, types.SimpleNamespace()
        )
        assert not result
        assert result.reason == "invalid_api_key"
        # Only authentication consulted the registry: reverification failed first.
        registry.get_active.assert_called_once_with(verified.jti)
        registry.is_active.assert_not_called()
        grant_check.assert_not_called()
        acl.assert_not_called()

    def test_reverification_error_propagates(self, jwt_request, verifier, verified):
        verifier.verify.side_effect = [verified, RuntimeError("verifier unavailable")]
        with pytest.raises(RuntimeError, match="verifier unavailable"):
            jwt_request.has_permission(Permissions.APIEcho, types.SimpleNamespace())

    def test_revoked_registry_entry_denies_authorization(
        self, jwt_request, verifier, verified, registry, grant_check, policy, mocker
    ):
        verifier.verify.return_value = verified
        registry.is_active.return_value = False
        acl = mocker.spy(policy._acl, "permits")
        assert jwt_request.identity is not None

        result = jwt_request.has_permission(
            Permissions.APIEcho, types.SimpleNamespace()
        )
        assert not result
        assert result.reason == "invalid_api_key"
        registry.get_active.assert_called_once_with(verified.jti)
        registry.is_active.assert_called_once_with(verified.jti)
        grant_check.assert_not_called()
        acl.assert_not_called()

    def test_registry_error_during_authorization_propagates(
        self, jwt_request, verifier, verified, registry, grant_check, policy, mocker
    ):
        verifier.verify.return_value = verified
        registry.is_active.side_effect = RuntimeError("registry unavailable")
        acl = mocker.spy(policy._acl, "permits")
        assert jwt_request.identity is not None

        with pytest.raises(RuntimeError, match="registry unavailable"):
            jwt_request.has_permission(Permissions.APIEcho, types.SimpleNamespace())
        grant_check.assert_not_called()
        acl.assert_not_called()
