# SPDX-License-Identifier: Apache-2.0
"""
Add JWT registry metadata

Revision ID: c2b8f04d6a91
Revises: b9d2a7e4c610
Create Date: 2026-10-22 00:00:00.000000
"""

import sqlalchemy as sa

from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c2b8f04d6a91"
down_revision = "b9d2a7e4c610"


def upgrade():
    op.add_column(
        "jwt_registry",
        sa.Column(
            "additional",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )


def downgrade():
    op.drop_column("jwt_registry", "additional")
