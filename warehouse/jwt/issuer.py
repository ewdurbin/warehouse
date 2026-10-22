# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import UUID

import jwt

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pyramid.exceptions import ConfigurationError
from zope.interface import implementer

from warehouse.jwt.claims import (
    AuthorizationDetail,
    ResourceRef,
    SignedJWT,
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry
from warehouse.jwt.profile import (
    MAX_LIFETIME_SECONDS,
    MEDIA_TYPE,
    valid_authorization_details,
)


@dataclass(frozen=True)
class WarehouseJWTIssuerFactory:
    """Immutable signing configuration shared by request-scoped issuers."""

    issuer: str
    audiences: Mapping[str, str]
    key_id: str
    key: RSAPrivateKey = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.issuer, str) or not self.issuer:
            raise ValueError("A JWT issuer is required")
        if not isinstance(self.key_id, str) or not self.key_id:
            raise ValueError("A JWT signing key ID is required")
        if not isinstance(self.key, RSAPrivateKey) or self.key.key_size < 2048:
            raise ValueError("JWT signing requires RSA private keys >= 2048 bits")
        if (
            not isinstance(self.audiences, Mapping)
            or not self.audiences
            or any(
                not isinstance(value, str) or not value
                for pair in self.audiences.items()
                for value in pair
            )
            or len(set(self.audiences.values())) != len(self.audiences)
        ):
            raise ValueError(
                "JWT audiences must have nonempty names and distinct values"
            )
        object.__setattr__(self, "audiences", MappingProxyType(dict(self.audiences)))

    @classmethod
    def from_settings(cls, settings):
        key_id = settings.get("warehouse.jwt.signing_key_id")
        pem = settings.get("warehouse.jwt.signing_key")
        public_keys = settings.get("warehouse.jwt.verification_keys")
        if (
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(pem, str)
            or not isinstance(public_keys, Mapping)
            or not isinstance(public_keys.get(key_id), str)
        ):
            raise ConfigurationError(
                "JWT signing requires a PEM private key and a key ID "
                "in verification_keys"
            )
        try:
            key = load_pem_private_key(pem.encode("utf-8"), password=None)
            factory = cls(
                issuer=settings.get("warehouse.jwt.issuer"),
                audiences={
                    name: settings.get(f"warehouse.jwt.{name}_audience")
                    for name in ("upload", "api")
                },
                key_id=key_id,
                key=key,
            )
            public_key = load_pem_public_key(public_keys[key_id].encode("utf-8"))
            if key.public_key() != public_key:
                raise ValueError(
                    "JWT signing key must match its configured verification key"
                )
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            # Do not include configuration values, especially the private key.
            raise ConfigurationError("Invalid JWT signing configuration") from exc
        return factory

    def __call__(self, context, request):
        return WarehouseJWTIssuer(
            registry=request.find_service(IJWTRegistry, context=None), config=self
        )


@implementer(IJWTIssuer)
class WarehouseJWTIssuer:
    """Sign authorized, server-selected claims and register their JTI atomically.

    Authorization of issuance belongs to the caller. Nothing here accepts an
    upstream OIDC assertion or changes the exchange endpoint's response format.
    """

    def __init__(self, *, registry, config: WarehouseJWTIssuerFactory):
        self.registry = registry
        self.config = config

    def issue(
        self,
        *,
        subject: SubjectRef,
        audience: str,
        authorization_details: tuple[AuthorizationDetail, ...],
        lifetime: int = MAX_LIFETIME_SECONDS,
        additional: dict | None = None,
    ) -> SignedJWT:
        if (
            not isinstance(subject, SubjectRef)
            or not isinstance(subject.kind, SubjectKind)
            or not isinstance(subject.id, UUID)
        ):
            raise ValueError("A typed JWT subject with a UUID is required")
        if not isinstance(audience, str) or audience not in self.config.audiences:
            raise ValueError("Unknown JWT audience name")
        if type(lifetime) is not int or not 0 < lifetime <= MAX_LIFETIME_SECONDS:
            raise ValueError(
                "JWT lifetime must be an integer between 1 and 300 seconds"
            )

        if not isinstance(authorization_details, tuple):
            raise ValueError("Typed JWT authorization details are required")
        details = []
        for detail in authorization_details:
            if not isinstance(detail, AuthorizationDetail) or not isinstance(
                detail.actions, tuple
            ):
                raise ValueError("Typed JWT authorization details are required")
            value = {"type": detail.type, "actions": list(detail.actions)}
            if detail.resource is not None:
                if not isinstance(detail.resource, ResourceRef) or not isinstance(
                    detail.resource.id, UUID
                ):
                    raise ValueError("A typed JWT resource with a UUID is required")
                value["identifier"] = f"{detail.resource.kind}:{detail.resource.id}"
            details.append(value)
        if not valid_authorization_details(details):
            raise ValueError("Invalid JWT authorization details")

        # Use the same integer NumericDate for the JWT and database expiration.
        issued_at = datetime.now(UTC).replace(microsecond=0)
        expires_at = issued_at + timedelta(seconds=lifetime)
        token_id = self.registry.register(expires_at, additional=additional)
        token = jwt.encode(
            {
                "iss": self.config.issuer,
                "aud": self.config.audiences[audience],
                "sub": str(subject.id),
                "subject_kind": subject.kind,
                "jti": str(token_id),
                "iat": int(issued_at.timestamp()),
                "exp": int(expires_at.timestamp()),
                "authorization_details": details,
            },
            self.config.key,
            algorithm="RS256",
            headers={"typ": MEDIA_TYPE, "kid": self.config.key_id},
        )
        return SignedJWT(token=token, jti=token_id, expires_at=expires_at)
