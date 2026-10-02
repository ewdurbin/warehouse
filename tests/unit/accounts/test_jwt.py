# SPDX-License-Identifier: Apache-2.0

import types

import pytest

from pyramid import testing
from pyramid.authorization import Allow, Authenticated
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import Request, apply_request_extensions
from pyramid.response import Response
from zope.interface.verify import verifyClass

from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.jwt import JWTSecurityPolicy, _extract_http_jwt
from warehouse.accounts.utils import UserContext
from warehouse.api.interfaces import IJWTVerifier
from warehouse.authnz import Permissions
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import AuthenticationMethod, MultiSecurityPolicy

TOKEN = "header.payload.signature"


@pytest.fixture
def verifier(mocker):
    service = mocker.Mock(spec=["verify", "permits"])
    service.verify.return_value = None
    service.permits.return_value = False
    return service


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
def jwt_request(policy, verifier, user_service):
    with testing.testConfig() as config:
        config.include("pyramid_services")
        config.register_service(verifier, IJWTVerifier)
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

    def test_invalid_token(self, jwt_request, verifier, user_service):
        assert jwt_request.identity is None
        verifier.verify.assert_called_once_with(TOKEN)
        user_service.get_user.assert_not_called()
        assert not hasattr(jwt_request, "authentication_method")

    def test_deleted_user(self, jwt_request, verifier, user_service, user):
        verifier.verify.return_value = user.id
        user_service.get_user.return_value = None
        assert jwt_request.identity is None
        user_service.get_user.assert_called_once_with(user.id)
        user_service.is_disabled.assert_not_called()

    def test_disabled_user(self, jwt_request, verifier, user_service, user):
        verifier.verify.return_value = user.id
        user_service.is_disabled.return_value = (True, "disabled")
        assert jwt_request.identity is None
        user_service.is_disabled.assert_called_once_with(user.id)

    def test_verified_user(self, jwt_request, verifier, user_service, user):
        verifier.verify.return_value = user.id
        assert jwt_request.identity == UserContext(user, macaroon=None)
        assert jwt_request.authenticated_userid == user.id
        assert jwt_request.authentication_method == AuthenticationMethod.API_KEY
        verifier.verify.assert_called_once_with(TOKEN)
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
        self, permission, jwt_request, verifier, user, policy, mocker
    ):
        verifier.verify.return_value = user.id
        verifier.permits.return_value = True
        acl = mocker.spy(policy._acl, "permits")
        result = jwt_request.has_permission(permission, types.SimpleNamespace())
        assert not result
        assert result.reason == "invalid_permission"
        verifier.permits.assert_not_called()
        acl.assert_not_called()

    def test_denies_token_restrictions(
        self, jwt_request, verifier, user, policy, mocker
    ):
        verifier.verify.return_value = user.id
        acl = mocker.spy(policy._acl, "permits")
        context = types.SimpleNamespace()
        result = jwt_request.has_permission(Permissions.APIEcho, context)
        assert not result
        assert result.reason == "invalid_api_key"
        verifier.permits.assert_called_once_with(
            TOKEN, jwt_request, context, Permissions.APIEcho
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
        self, permission, principal, jwt_request, verifier, user
    ):
        verifier.verify.return_value = user.id
        verifier.permits.return_value = True
        context = types.SimpleNamespace(__acl__=[(Allow, principal, permission)])
        assert bool(jwt_request.has_permission(permission, context)) == (
            principal == "user:test"
        )

    def test_authorizes_the_original_credential(self, jwt_request, verifier, user):
        verifier.verify.return_value = user.id
        verifier.permits.return_value = True
        assert jwt_request.identity == UserContext(user, macaroon=None)
        jwt_request.headers["Authorization"] = "Bearer different.token.signature"
        context = types.SimpleNamespace(
            __acl__=[(Allow, "user:test", Permissions.APIEcho)]
        )
        assert jwt_request.has_permission(Permissions.APIEcho, context)
        verifier.verify.assert_called_once_with(TOKEN)
        verifier.permits.assert_called_once_with(
            TOKEN, jwt_request, context, Permissions.APIEcho
        )

    def test_verifier_error_does_not_authenticate(self, jwt_request, verifier):
        verifier.verify.side_effect = RuntimeError("verifier unavailable")
        with pytest.raises(RuntimeError, match="verifier unavailable"):
            _ = jwt_request.identity

    def test_authorization_error_does_not_allow(self, jwt_request, verifier, user):
        verifier.verify.return_value = user.id
        verifier.permits.side_effect = RuntimeError("verifier unavailable")
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
