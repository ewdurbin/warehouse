# SPDX-License-Identifier: Apache-2.0

from pyramid.authorization import ACLHelper
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import RequestLocalCache
from zope.interface import implementer

from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
from warehouse.cache.http import add_vary_callback
from warehouse.errors import WarehouseDenied
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.predicates import auth_methods_for_route
from warehouse.utils.security_policy import (
    AuthenticationMethod,
    permission_allowed_by_authentication_method,
    principals_for,
)


@RequestLocalCache()
def _extract_http_jwt(request):
    """Extract a candidate JWT, without treating its contents as verified.

    Cache the credential so identity and authorization use the same token.
    Bearer macaroons remain the responsibility of MacaroonSecurityPolicy.
    """
    authorization = request.headers.get("Authorization", "").split()
    if len(authorization) != 2:
        return None

    scheme, token = authorization
    if scheme.lower() != "bearer" or token.startswith("pypi-"):
        return None

    return token


@implementer(ISecurityPolicy)
class JWTSecurityPolicy:
    """Authenticate JWT-backed API keys on explicitly opted-in routes."""

    def __init__(self):
        self._acl = ACLHelper()

    def identity(self, request):
        request.add_response_callback(add_vary_callback("Authorization"))

        if not request.matched_route:
            return None

        allowed = auth_methods_for_route(request.matched_route)
        if allowed is None or AuthenticationMethod.API_KEY not in allowed:
            return None

        token = _extract_http_jwt(request)
        if token is None:
            return None

        verifier = request.find_service(IJWTVerifier, context=None)
        userid = verifier.verify(token)
        if userid is None:
            return None

        user_service = request.find_service(IUserService, context=None)
        user = user_service.get_user(userid)
        if user is None:
            return None

        is_disabled, _ = user_service.is_disabled(user.id)
        if is_disabled:
            return None

        request.authentication_method = AuthenticationMethod.API_KEY
        return UserContext(user, macaroon=None)

    def authenticated_userid(self, request):
        # Handled by MultiSecurityPolicy.
        raise NotImplementedError

    def remember(self, request, userid, **kw):
        return []

    def forget(self, request, **kw):
        return []

    def permits(self, request, context, permission):
        token = _extract_http_jwt(request)
        assert isinstance(token, str), "no JWT credential"
        assert isinstance(request.identity, UserContext)
        assert request.identity.macaroon is None

        if not permission_allowed_by_authentication_method(
            permission, AuthenticationMethod.API_KEY
        ):
            return WarehouseDenied(
                f"API keys are not valid for permission: {permission}!",
                reason="invalid_permission",
            )

        verifier = request.find_service(IJWTVerifier, context=None)
        if not verifier.permits(token, request, context, permission):
            return WarehouseDenied(
                "Invalid or insufficiently scoped API key",
                reason="invalid_api_key",
            )

        return self._acl.permits(context, principals_for(request.identity), permission)
