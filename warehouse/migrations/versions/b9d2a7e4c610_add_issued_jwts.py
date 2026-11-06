# SPDX-License-Identifier: Apache-2.0
"""
Add the issued JWTs table

Revision ID: b9d2a7e4c610
Revises: f555f02f7688
Create Date: 2026-10-22 00:00:00.000000
"""

import sqlalchemy as sa

from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b9d2a7e4c610"
down_revision = "f555f02f7688"


def upgrade():
    op.create_table(
        "issued_jwts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "additional",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_issued_jwts_expires_at", "issued_jwts", ["expires_at"])


def downgrade():
    op.drop_index("ix_issued_jwts_expires_at", table_name="issued_jwts")
    op.drop_table("issued_jwts")
