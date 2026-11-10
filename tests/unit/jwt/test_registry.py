# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid7

import pytest

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.services import DatabaseJWTRegistry


class TestDatabaseJWTRegistry:
    def test_register(self, jwt_registry, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        first = jwt_registry.register(expires_at)
        second = jwt_registry.register(expires_at)

        assert first.version == second.version == 7
        assert first != second
        entry = jwt_registry.get_active(first)
        assert entry is not None
        assert entry.expires_at == expires_at
        assert entry.additional == {}

    def test_metadata_roundtrip(self, jwt_registry, db_session, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        local_expiry = expires_at.astimezone(timezone(timedelta(hours=5)))
        additional = {"oidc": {"sha": "abc", "ref": "refs/tags/v1"}}
        token_id = jwt_registry.register(local_expiry, additional=additional)
        additional["oidc"]["sha"] = "changed"
        db_session.flush()
        db_session.expire_all()

        entry = jwt_registry.get_active(token_id)
        assert entry is not None
        assert entry.id == token_id
        assert entry.expires_at == expires_at
        assert entry.expires_at.utcoffset() == timedelta(0)
        assert entry.additional == {"oidc": {"sha": "abc", "ref": "refs/tags/v1"}}

    def test_register_requires_timezone(self, jwt_registry, clock):
        expires_at = (datetime.now(UTC) + timedelta(minutes=5)).replace(tzinfo=None)
        with pytest.raises(ValueError, match="timezone-aware"):
            jwt_registry.register(expires_at)

    def test_register_requires_future_expiry(self, jwt_registry, clock):
        with pytest.raises(ValueError, match="in the future"):
            jwt_registry.register(datetime.now(UTC))

    def test_metadata_requires_dictionary(self, jwt_registry, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        with pytest.raises(ValueError, match="metadata must be a dictionary"):
            jwt_registry.register(expires_at, additional=[])

    def test_register_can_be_rolled_back(self, jwt_registry, db_session, clock):
        with db_session.begin_nested() as transaction:
            token_id = jwt_registry.register(datetime.now(UTC) + timedelta(minutes=5))
            assert jwt_registry.is_active(token_id)
            transaction.rollback()

        assert not jwt_registry.is_active(token_id)
        assert jwt_registry.get_active(token_id) is None

    def test_missing_is_inactive(self, jwt_registry):
        token_id = uuid7()
        assert not jwt_registry.is_active(token_id)
        assert jwt_registry.get_active(token_id) is None

    def test_expiry_without_cleanup(self, jwt_registry, db_session, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        token_id = jwt_registry.register(expires_at)
        clock.move_to(expires_at - timedelta(microseconds=1))

        assert jwt_registry.is_active(token_id)
        assert jwt_registry.get_active(token_id) is not None

        clock.move_to(expires_at)
        assert not jwt_registry.is_active(token_id)
        assert jwt_registry.get_active(token_id) is None
        assert not jwt_registry.revoke(token_id)
        assert db_session.get(IssuedJWT, token_id) is not None

    def test_revoke(self, jwt_registry, db_session, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        token_id = jwt_registry.register(expires_at)
        other_id = jwt_registry.register(expires_at)

        assert jwt_registry.revoke(token_id)
        assert not jwt_registry.revoke(token_id)

        assert not jwt_registry.is_active(token_id)
        assert jwt_registry.get_active(token_id) is None
        assert db_session.get(IssuedJWT, token_id) is None
        assert jwt_registry.is_active(other_id)

    def test_revoke_can_be_rolled_back(self, jwt_registry, db_session, clock):
        token_id = jwt_registry.register(datetime.now(UTC) + timedelta(minutes=5))
        with db_session.begin_nested() as transaction:
            jwt_registry.revoke(token_id)
            assert not jwt_registry.is_active(token_id)
            transaction.rollback()

        assert jwt_registry.is_active(token_id)

    def test_sees_committed_revocation_with_cached_identity(self, app_config, clock):
        engine = app_config.registry["sqlalchemy.engine"]
        with Session(engine) as writer, Session(engine) as reader:
            issuer = DatabaseJWTRegistry(writer)
            verifier = DatabaseJWTRegistry(reader)
            token_id = issuer.register(datetime.now(UTC) + timedelta(minutes=5))
            writer.commit()
            try:
                cached_token = verifier.get_active(token_id)
                assert cached_token is not None

                issuer.revoke(token_id)
                assert verifier.is_active(token_id)
                assert verifier.get_active(token_id) is cached_token

                writer.commit()
                assert reader.get(IssuedJWT, token_id) is cached_token
                assert not verifier.is_active(token_id)
                assert verifier.get_active(token_id) is None
            finally:
                reader.rollback()
                issuer.revoke(token_id)
                writer.commit()

    def test_lookup_propagates_database_failure(self, jwt_registry, db_session, mocker):
        mocker.patch.object(
            db_session,
            "scalar",
            side_effect=OperationalError(
                "statement", {}, Exception("database unavailable")
            ),
        )
        with pytest.raises(OperationalError):
            jwt_registry.is_active(uuid7())
