# SPDX-License-Identifier: Apache-2.0

from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import JSONB

from warehouse.jwt.models import IssuedJWT


def test_schema(db_session):
    inspector = inspect(db_session.connection())
    table_name = IssuedJWT.__tablename__
    columns = {column["name"]: column for column in inspector.get_columns(table_name)}
    assert isinstance(columns["additional"]["type"], JSONB)
    assert columns["additional"]["default"] == "'{}'::jsonb"
    assert inspector.get_pk_constraint(table_name)["constrained_columns"] == ["id"]
    assert any(
        index["column_names"] == ["expires_at"]
        for index in inspector.get_indexes(table_name)
    )
