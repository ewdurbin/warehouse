# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid7

from sqlalchemy import delete, select
from zope.interface import implementer

from warehouse.jwt.claims import VerifiedJWT
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.models import IssuedJWT


@implementer(IJWTVerifier)
class DisabledJWTVerifier:
    """Reject every JWT."""

    @classmethod
    def create_service(cls, context, request):
        return cls()

    def verify(self, token: str) -> VerifiedJWT | None:
        return None


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


def jwt_verifier_factory(settings):
    """Enable JWT verification when public keys are configured."""
    if "warehouse.jwt.verification_keys" not in settings:
        return DisabledJWTVerifier.create_service

    # The verifier factory also imports DisabledJWTVerifier from this module.
    from warehouse.jwt.verifier import WarehouseJWTVerifierFactory  # noqa: PLC0415

    return WarehouseJWTVerifierFactory(settings)
