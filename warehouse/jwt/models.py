# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
from uuid import UUID, uuid7

from sqlalchemy import DateTime, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from warehouse import db


class IssuedJWT(db.Model):
    __tablename__ = "jwt_registry"

    # Override the shared model's PostgreSQL UUIDv4 default for this table only.
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid7)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    # Per-issuance metadata, not an alternate source of authorization claims.
    additional: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
