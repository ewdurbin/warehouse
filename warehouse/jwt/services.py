# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

from sqlalchemy import delete, exists, select
from zope.interface import implementer

from warehouse.jwt.claims import VerifiedJWT
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS


@implementer(IJWTVerifier)
class DisabledJWTVerifier:
    """Reject every JWT."""

    @classmethod
    def create_service(cls, context, request):
        return cls()

    def verify(self, token: str) -> VerifiedJWT | None:
        return None


@implementer(IJWTRegistry)
class DatabaseJWTRegistry:
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
        # Refresh the entry even if this session already loaded it.
        return self.db.scalar(
            select(IssuedJWT)
            .where(
                IssuedJWT.id == token_id,
                IssuedJWT.expires_at > datetime.now(UTC),
            )
            .execution_options(populate_existing=True)
        )

    def is_active(self, token_id: UUID) -> bool:
        # READ COMMITTED sees revocations committed before this query.
        # Session.get() could return a cached row.
        return bool(
            self.db.scalar(
                select(
                    exists().where(
                        IssuedJWT.id == token_id,
                        IssuedJWT.expires_at > datetime.now(UTC),
                    )
                )
            )
        )

    def revoke(self, token_id: UUID) -> None:
        self.db.execute(
            delete(IssuedJWT)
            .where(IssuedJWT.id == token_id)
            .execution_options(synchronize_session=False)
        )

    def delete_expired(self) -> int:
        # Allow for bounded clock skew between cleanup workers and verifiers.
        cutoff = datetime.now(UTC) - timedelta(seconds=MAX_LIFETIME_SECONDS)
        result = self.db.execute(
            delete(IssuedJWT)
            .where(IssuedJWT.expires_at <= cutoff)
            .execution_options(synchronize_session=False)
        )
        return result.rowcount
