# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType

import jwt

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pyramid.exceptions import ConfigurationError
from zope.interface import implementer

from warehouse.jwt.claims import (
    SubjectKind,
    SubjectRef,
    VerifiedJWT,
)
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.profile import (
    MAX_LIFETIME_SECONDS,
    MAX_TOKEN_LENGTH,
    MEDIA_TYPE,
    parse_authorization_details,
    parse_uuid,
)
from warehouse.jwt.services import DisabledJWTVerifier

_REQUIRED_CLAIMS = {
    "iss",
    "aud",
    "sub",
    "subject_kind",
    "jti",
    "iat",
    "exp",
    "authorization_details",
}


class WarehouseJWTVerifierFactory:
    """Load verifier settings once and select the audience from the matched route.

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
        # Route metadata imports account/organization models. Keep that dependency
        # at request-time so the verifier can also be imported before app setup.
        from warehouse.predicates import (  # noqa: PLC0415
            auth_methods_for_route,
            jwt_audience_for_route,
        )
        from warehouse.utils.security_policy import (  # noqa: PLC0415
            AuthenticationMethod,
        )

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


@implementer(IJWTVerifier)
class WarehouseJWTVerifier:
    """Verify Warehouse-issued JWTs against the configured issuer and audience.

    Verification uses the configured public keys. Callers resolve identities,
    check the registry, and enforce permissions separately.
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
            # Use kid only to look up a configured key. Accept just the header
            # fields, algorithm, and type defined by the profile.
            if (
                set(header) != {"alg", "kid", "typ"}
                or header["alg"] != "RS256"
                or header["typ"] != MEDIA_TYPE
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
                    "strict_aud": True,
                },
            )
        except jwt.InvalidTokenError:
            return None

        # An unknown claim could express a restriction we cannot enforce.
        # Require integer timestamps even if PyJWT accepts a coercible value.
        if claims.keys() - (_REQUIRED_CLAIMS | {"nbf"}):
            return None
        if any(type(claims[c]) is not int for c in ("iat", "exp")):
            return None
        if "nbf" in claims and type(claims["nbf"]) is not int:
            return None
        # Measure lifetime from issuance even when nbf is present.
        if not 0 < claims["exp"] - claims["iat"] <= MAX_LIFETIME_SECONDS:
            return None
        if claims["subject_kind"] not in (SubjectKind.USER, SubjectKind.PUBLISHER):
            return None
        return claims

    def verify(self, token: str) -> VerifiedJWT | None:
        if len(token) > MAX_TOKEN_LENGTH or not token.isascii() or "=" in token:
            return None
        if (claims := self._claims(token)) is None:
            return None
        jti = parse_uuid(claims["jti"])
        subject_id = parse_uuid(claims["sub"])
        if jti is None or subject_id is None:
            return None
        details = parse_authorization_details(claims["authorization_details"])
        if details is None:
            return None
        return VerifiedJWT(
            jti=jti,
            subject=SubjectRef(SubjectKind(claims["subject_kind"]), subject_id),
            issuer=claims["iss"],
            audience=claims["aud"],
            issued_at=datetime.fromtimestamp(claims["iat"], UTC),
            expires_at=datetime.fromtimestamp(claims["exp"], UTC),
            authorization_details=details,
        )
