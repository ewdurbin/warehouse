# SPDX-License-Identifier: Apache-2.0

from pyramid.authorization import ACLHelper
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import RequestLocalCache
from zope.interface import implementer

from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
from warehouse.cache.http import add_vary_callback
from warehouse.errors import WarehouseDenied
from warehouse.jwt import authorization
from warehouse.jwt.claims import SubjectKind
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.oidc.models import OIDCPublisher
from warehouse.oidc.utils import PublisherTokenContext
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
        if allowed is None or AuthenticationMethod.JWT not in allowed:
            return None

        token = _extract_http_jwt(request)
        if token is None:
            return None

        verifier = request.find_service(IJWTVerifier, context=None)
        verified = verifier.verify(token)
        if verified is None:
            return None

        registry = request.find_service(IJWTRegistry, context=None)
        entry = registry.get_active(verified.jti)
        if entry is None:
            return None

        # Resolve only the explicitly named kind. A UUID missing from one table
        # must never fall back to another kind of identity.
        if verified.subject.kind == SubjectKind.USER:
            user_service = request.find_service(IUserService, context=None)
            user = user_service.get_user(str(verified.subject.id))
            if user is None:
                return None
            is_disabled, _ = user_service.is_disabled(user.id)
            if is_disabled:
                return None
            identity = UserContext(user, macaroon=None)
        elif verified.subject.kind == SubjectKind.PUBLISHER:
            publisher = request.db.get(OIDCPublisher, verified.subject.id)
            if publisher is None:
                return None
            identity = PublisherTokenContext(
                publisher, claims=entry.additional.get("oidc")
            )
        else:
            return None

        request.authentication_method = AuthenticationMethod.JWT
        return identity

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

        if not permission_allowed_by_authentication_method(
            permission, AuthenticationMethod.JWT
        ):
            return WarehouseDenied(
                f"API keys are not valid for permission: {permission}!",
                reason="invalid_permission",
            )

        verifier = request.find_service(IJWTVerifier, context=None)
        # Like macaroons, cached identity does not bypass credential validation.
        verified = verifier.verify(token)
        registry = request.find_service(IJWTRegistry, context=None)
        if (
            verified is None
            or not registry.is_active(verified.jti)
            or not authorization.permits(
                verified, request.identity, context, permission
            )
        ):
            return WarehouseDenied(
                "Invalid or insufficiently scoped API key",
                reason="invalid_api_key",
            )

        return self._acl.permits(context, principals_for(request.identity), permission)
