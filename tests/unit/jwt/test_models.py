# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import JSONB

from warehouse.jwt.models import IssuedJWT


def test_schema(db_session):
    inspector = inspect(db_session.connection())
    table_name = "issued_jwts"
    columns = {column["name"]: column for column in inspector.get_columns(table_name)}
    assert set(columns) == {"id", "expires_at", "additional"}
    assert columns["id"]["default"] is None
    assert columns["id"]["nullable"] is False
    assert columns["expires_at"]["nullable"] is False
    assert columns["expires_at"]["type"].timezone is True
    assert isinstance(columns["additional"]["type"], JSONB)
    assert columns["additional"]["nullable"] is False
    assert columns["additional"]["default"] == "'{}'::jsonb"
    assert inspector.get_pk_constraint(table_name)["constrained_columns"] == ["id"]
    assert any(
        index["column_names"] == ["expires_at"]
        for index in inspector.get_indexes(table_name)
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
