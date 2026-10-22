# SPDX-License-Identifier: Apache-2.0
"""
Add the issued JWT registry

Revision ID: b9d2a7e4c610
Revises: f555f02f7688
Create Date: 2026-10-22 00:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "b9d2a7e4c610"
down_revision = "f555f02f7688"


def upgrade():
    op.create_table(
        "jwt_registry",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_jwt_registry_expires_at", "jwt_registry", ["expires_at"])


def downgrade():
    op.drop_index("ix_jwt_registry_expires_at", table_name="jwt_registry")
    op.drop_table("jwt_registry")
