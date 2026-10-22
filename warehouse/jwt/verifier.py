# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType

import jwt

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from zope.interface import implementer

from warehouse.jwt.claims import (
    SubjectKind,
    SubjectRef,
    VerifiedJWT,
)
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.profile import (
    MAX_LIFETIME_SECONDS,
    MEDIA_TYPE,
    parse_authorization_details,
    parse_uuid,
)

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


@implementer(IJWTVerifier)
class WarehouseJWTVerifier:
    """Verify Warehouse-issued, explicitly scoped API keys.

    Keys are supplied by trusted configuration, never by a token or remote URL.
    Each environment has one issuer and separate upload and API audiences. Each
    verifier requires the exact audience configured for its intended recipient.
    RFC 9396 authorization details permit actions with optional resource narrowing.
    Verification does not resolve the subject or authorize a request or resource.
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
