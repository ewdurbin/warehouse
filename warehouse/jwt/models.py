# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from warehouse import db


class IssuedJWT(db.Model):
    __tablename__ = "issued_jwts"

    # The registry assigns the UUIDv7 before flushing the row.
    id: Mapped[UUID] = mapped_column(primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    # Issuance metadata used for provenance, such as upstream OIDC claims.
    additional: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
