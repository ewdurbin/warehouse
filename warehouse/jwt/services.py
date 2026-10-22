# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid7

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pyramid.exceptions import ConfigurationError
from sqlalchemy import delete, select
from zope.interface import implementer

from warehouse.jwt.claims import AuthorizationDetail, SignedJWT, SubjectRef, VerifiedJWT
from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTVerifier
from warehouse.jwt.issuer import WarehouseJWTIssuerFactory
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS
from warehouse.jwt.verifier import WarehouseJWTVerifier
from warehouse.predicates import auth_methods_for_route, jwt_audience_for_route
from warehouse.utils.security_policy import AuthenticationMethod


def jwt_issuer_factory(settings):
    """Build the issuer factory with the configured issuer and audiences."""
    try:
        return WarehouseJWTIssuerFactory(
            issuer=settings.get("warehouse.jwt.issuer"),
            audiences={
                name: settings.get(f"warehouse.jwt.{name}_audience")
                for name in ("upload", "api")
            },
        )
    except ValueError as exc:
        raise ConfigurationError("Invalid JWT issuance configuration") from exc


@implementer(IJWTIssuer)
class DisabledJWTIssuer:
    enabled = False

    def issue(
        self,
        *,
        subject: SubjectRef,
        audience: str,
        authorization_details: tuple[AuthorizationDetail, ...],
        lifetime: int = MAX_LIFETIME_SECONDS,
        additional: dict | None = None,
    ) -> SignedJWT:
        raise RuntimeError("JWT issuance is disabled")


@implementer(IJWTVerifier)
class DisabledJWTVerifier:
    """Reject every JWT."""

    @classmethod
    def create_service(cls, context, request):
        return cls()

    def verify(self, token: str) -> VerifiedJWT | None:
        return None


class WarehouseJWTVerifierFactory:
    """Load verification keys at startup and select an audience by route."""

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

    def for_audience(self, name):
        """Return a verifier factory for an audience chosen by the caller.

        Use a server-selected name, as the burn endpoint does for upload tokens.
        """
        verifier = self._verifiers[name]
        return lambda context, request: verifier

    def __call__(self, context, request):
        route = request.matched_route
        if route is not None:
            methods = auth_methods_for_route(route)
            audience = jwt_audience_for_route(route)
            if audience is not None and AuthenticationMethod.JWT in (methods or ()):
                return self._verifiers[audience]
        return DisabledJWTVerifier()


def jwt_verifier_factory(settings):
    """Enable JWT verification when public keys are configured."""
    if "warehouse.jwt.verification_keys" not in settings:
        return DisabledJWTVerifier.create_service
    return WarehouseJWTVerifierFactory(settings)


def _active_jwt_conditions(token_id: UUID):
    return IssuedJWT.id == token_id, IssuedJWT.expires_at > datetime.now(UTC)


@implementer(IJWTRegistry)
class DatabaseJWTRegistry:
    """Query PostgreSQL for liveness even when the session has cached the row."""

    def __init__(self, db_session):
        self.db = db_session

    @classmethod
    def create_service(cls, context, request):
        return cls(request.db)

    def register(self, expires_at: datetime, *, additional: dict | None = None) -> UUID:
        if expires_at.utcoffset() is None:
            raise ValueError("JWT expiration must be timezone-aware")
        expires_at = expires_at.astimezone(UTC)
        if expires_at <= datetime.now(UTC):
            raise ValueError("JWT expiration must be in the future")
        if additional is not None and not isinstance(additional, dict):
            raise ValueError("JWT metadata must be a dictionary")

        # Give the issuer a token ID before SQLAlchemy flushes the new row.
        token = IssuedJWT(
            id=uuid7(), expires_at=expires_at, additional=deepcopy(additional or {})
        )
        self.db.add(token)
        return token.id

    def get_active(self, token_id: UUID) -> IssuedJWT | None:
        return self.db.scalar(
            select(IssuedJWT).where(*_active_jwt_conditions(token_id))
        )

    def is_active(self, token_id: UUID) -> bool:
        return (
            self.db.scalar(
                select(IssuedJWT.id).where(*_active_jwt_conditions(token_id))
            )
            is not None
        )

    def revoke(self, token_id: UUID) -> None:
        self.db.execute(
            delete(IssuedJWT)
            .where(IssuedJWT.id == token_id)
            .execution_options(synchronize_session=False)
        )
