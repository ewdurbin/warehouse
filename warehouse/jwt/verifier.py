# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from types import MappingProxyType
from uuid import UUID

import jwt

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pyramid.exceptions import ConfigurationError
from zope.interface import implementer

from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.services import DisabledJWTVerifier
from warehouse.packaging.models import Project
from warehouse.predicates import auth_methods_for_route, jwt_audience_for_route
from warehouse.utils.security_policy import AuthenticationMethod

_MEDIA_TYPE = "warehouse-api-key+jwt"
_MAX_LIFETIME_SECONDS = 300
_REQUIRED_CLAIMS = {"iss", "aud", "sub", "iat", "exp", "permissions", "project_ids"}
_PERMISSIONS = {
    Permissions.ProjectsUpload,
    Permissions.APIEcho,
    Permissions.APIObservationsAdd,
}


class WarehouseJWTVerifierFactory:
    """Load trusted configuration once; select a verifier from the matched route.

    Neither token claims nor request host/path/headers determine the audience.
    Routes must explicitly declare a jwt_audience and opt into API_KEY.
    """

    def __init__(self, settings):
        issuer = settings.get("warehouse.jwt.issuer")
        audiences = {
            name: settings.get(f"warehouse.jwt.{name}_audience")
            for name in ("upload", "api")
        }
        if audiences["upload"] == audiences["api"]:
            raise ConfigurationError("JWT upload and API audiences must be distinct")
        configured_keys = settings.get("warehouse.jwt.verification_keys")
        if not isinstance(configured_keys, Mapping) or not configured_keys:
            raise ConfigurationError(
                "warehouse.jwt.verification_keys must map key IDs to PEM public keys"
            )
        keys = {}
        for kid, pem in configured_keys.items():
            if not isinstance(pem, str):
                raise ConfigurationError("JWT verification keys must be PEM strings")
            try:
                keys[kid] = load_pem_public_key(pem.encode("utf-8"))
            except (ValueError, UnsupportedAlgorithm) as exc:
                raise ConfigurationError("Invalid JWT PEM public key") from exc
        try:
            self._verifiers = {
                name: WarehouseJWTVerifier(issuer=issuer, audience=audience, keys=keys)
                for name, audience in audiences.items()
            }
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc

    def __call__(self, context, request):
        route = request.matched_route
        if route is not None:
            methods = auth_methods_for_route(route)
            audience_name = jwt_audience_for_route(route)
            if (
                audience_name is not None
                and methods is not None
                and AuthenticationMethod.API_KEY in methods
            ):
                return self._verifiers[audience_name]
        return DisabledJWTVerifier()


def _is_uuid(value) -> bool:
    """Require the canonical string representation of a Warehouse ID."""
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


@implementer(IJWTVerifier)
class WarehouseJWTVerifier:
    """Verify Warehouse-issued, explicitly scoped API keys.

    Keys are supplied by trusted configuration, never by a token or remote URL.
    Each environment has one issuer and separate upload and API audiences. Each
    verifier requires the exact audience configured for its intended recipient.
    Permissions additionally restrict what each token can do.
    This class is deliberately not registered as the default verifier yet.
    It does not mint tokens or provide per-token revocation.
    """

    def __init__(self, *, issuer: str, audience: str, keys: Mapping[str, RSAPublicKey]):
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("A JWT issuer is required")
        if not isinstance(audience, str) or not audience:
            raise ValueError("A JWT audience is required")
        if not keys:
            raise ValueError("At least one JWT verification key is required")
        for kid, key in keys.items():
            if not isinstance(kid, str) or not kid:
                raise ValueError("JWT key IDs must be nonempty strings")
            if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                raise ValueError(
                    "JWT verification requires RSA public keys >= 2048 bits"
                )

        self._issuer = issuer
        self._audience = audience
        self._keys = MappingProxyType(dict(keys))

    def _claims(self, token: str) -> dict | None:
        try:
            header = jwt.get_unverified_header(token)
            # The unverified header may only select a preconfigured key. Reject
            # unsupported JOSE extensions as well as other token types/algorithms.
            if (
                set(header) != {"alg", "kid", "typ"}
                or header["alg"] != "RS256"
                or header["typ"] != _MEDIA_TYPE
                or not isinstance(header["kid"], str)
            ):
                return None
            key = self._keys.get(header["kid"])
            if key is None:
                return None
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": sorted(_REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_sub": True,
                    "verify_iat": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "strict_aud": True,
                },
            )
        except jwt.InvalidTokenError:
            return None

        # Unknown claims could express restrictions a future verifier supports;
        # do not silently ignore them. NumericDates must be integers, not values
        # that PyJWT can coerce to integers (including booleans).
        if claims.keys() - (_REQUIRED_CLAIMS | {"nbf"}):
            return None
        if any(type(claims[c]) is not int for c in ("iat", "exp")):
            return None
        if "nbf" in claims and type(claims["nbf"]) is not int:
            return None
        # Bound the issued lifetime, not the time remaining or the nbf window.
        if not 0 < claims["exp"] - claims["iat"] <= _MAX_LIFETIME_SECONDS:
            return None
        if not _is_uuid(claims["sub"]):
            return None
        permissions = claims["permissions"]
        if not isinstance(permissions, list) or not permissions:
            return None
        if any(not isinstance(p, str) or p not in _PERMISSIONS for p in permissions):
            return None
        project_ids = claims["project_ids"]
        if not isinstance(project_ids, list) or any(
            not _is_uuid(project_id) for project_id in project_ids
        ):
            return None
        return claims

    def verify(self, token: str) -> str | None:
        if (claims := self._claims(token)) is None:
            return None
        return claims["sub"]

    def permits(self, token: str, request, context, permission) -> bool:
        # Reverify, including expiration, even if identity was cached earlier.
        if (claims := self._claims(token)) is None:
            return False
        identity = request.identity
        if (
            not isinstance(identity, UserContext)
            or identity.macaroon is not None
            or str(identity.user.id) != claims["sub"]
        ):
            return False
        if (
            not isinstance(permission, Permissions)
            or permission not in claims["permissions"]
        ):
            return False
        # Echo has no project resource. Both upload and observations require an
        # explicitly named project; an empty list grants no project access.
        if permission == Permissions.APIEcho:
            return True
        return isinstance(context, Project) and str(context.id) in claims["project_ids"]
