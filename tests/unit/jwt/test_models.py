# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text
from sqlalchemy.dialects.postgresql import JSONB

from warehouse.jwt.models import IssuedJWT
from warehouse.migrations.versions import (
    c2b8f04d6a91_add_jwt_registry_metadata as migration,
)


def test_schema(db_session):
    inspector = inspect(db_session.connection())
    columns = {
        column["name"]: column for column in inspector.get_columns("jwt_registry")
    }
    assert set(columns) == {"id", "expires_at", "additional"}
    assert columns["id"]["default"] is None
    assert columns["id"]["nullable"] is False
    assert columns["expires_at"]["nullable"] is False
    assert columns["expires_at"]["type"].timezone is True
    assert isinstance(columns["additional"]["type"], JSONB)
    assert columns["additional"]["nullable"] is False
    assert columns["additional"]["default"] == "'{}'::jsonb"
    assert inspector.get_pk_constraint("jwt_registry")["constrained_columns"] == ["id"]
    assert any(
        index["column_names"] == ["expires_at"]
        for index in inspector.get_indexes("jwt_registry")
    )


def test_model_defaults_and_roundtrip(db_session):
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    token = IssuedJWT(expires_at=expires_at)
    db_session.add(token)
    db_session.flush()
    token_id = token.id
    db_session.expire_all()

    assert isinstance(token.id, UUID)
    assert token.id.version == 7
    assert token.id == token_id
    assert token.expires_at == expires_at
    assert token.expires_at.utcoffset() == timedelta(0)
    assert token.additional == {}


def test_metadata_migration_preserves_existing_entries(db_session):
    token_id = uuid7()
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    # Exercise upgrade and downgrade only inside the test DB transaction.
    with db_session.begin_nested() as transaction:
        with Operations.context(MigrationContext.configure(db_session.connection())):
            migration.downgrade()
            db_session.execute(
                text(
                    "INSERT INTO jwt_registry (id, expires_at) "
                    "VALUES (:id, :expires_at)"
                ),
                {"id": token_id, "expires_at": expires_at},
            )
            migration.upgrade()
        token = db_session.get(IssuedJWT, token_id)
        assert token.additional == {}
        assert token.expires_at == expires_at
        transaction.rollback()
