# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime
from uuid import UUID, uuid7

from sqlalchemy import delete, exists, select
from zope.interface import implementer

from warehouse.jwt.interfaces import IJWTRegistry
from warehouse.jwt.models import IssuedJWT


@implementer(IJWTRegistry)
class DatabaseJWTRegistry:
    def __init__(self, db_session):
        self.db = db_session

    @classmethod
    def create_service(cls, context, request):
        return cls(request.db)

    def register(self, expires_at: datetime) -> UUID:
        if expires_at.utcoffset() is None:
            raise ValueError("JWT expiration must be timezone-aware")
        expires_at = expires_at.astimezone(UTC)
        if expires_at <= datetime.now(UTC):
            raise ValueError("JWT expiration must be in the future")

        # Assign before insertion so the issuer can build the JWT without an
        # explicit flush. The caller must commit before handing out the token.
        token = IssuedJWT(id=uuid7(), expires_at=expires_at)
        self.db.add(token)
        return token.id

    def is_active(self, token_id: UUID) -> bool:
        # Do not use Session.get(): an ORM identity-map hit could hide revocation
        # committed by another request. READ COMMITTED sees a fresh snapshot.
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
        result = self.db.execute(
            delete(IssuedJWT)
            .where(IssuedJWT.expires_at <= datetime.now(UTC))
            .execution_options(synchronize_session=False)
        )
        return result.rowcount
