# SPDX-License-Identifier: Apache-2.0

import types

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid7

import pytest

from freezegun import freeze_time
from psycopg.errors import UniqueViolation
from pyramid import testing
from pyramid.request import Request, apply_request_extensions
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from zope.interface.verify import verifyClass

from warehouse.authnz import Permissions
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTVerifier,
    jwt_verifier_factory,
)
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import MultiSecurityPolicy


class TestDisabledJWTVerifier:
    def test_default_needs_no_configuration(self):
        assert jwt_verifier_factory({}) == DisabledJWTVerifier.create_service

    def test_interface(self):
        assert verifyClass(IJWTVerifier, DisabledJWTVerifier)

    @pytest.mark.parametrize("token", ["", "garbage", "header.payload.signature"])
    def test_rejects_all_tokens(self, token):
        verifier = DisabledJWTVerifier()
        assert verifier.verify(token) is None

    def test_service_factory(self):
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service_factory(
                DisabledJWTVerifier.create_service, IJWTVerifier
            )
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/")
            request.registry = config.registry
            apply_request_extensions(request)
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"api-key"}, None)]
            )
            request.headers["Authorization"] = "Bearer header.payload.signature"
            verifier = request.find_service(IJWTVerifier, context=None)
            assert isinstance(verifier, DisabledJWTVerifier)
            assert verifier.verify("header.payload.signature") is None
            assert request.identity is None
            assert not request.has_permission(
                Permissions.ProjectsUpload, types.SimpleNamespace()
            )


@pytest.fixture
def clock():
    with freeze_time("2026-10-22 00:00:00+00:00", ignore=["_pytest"]) as clock:
        yield clock


class TestDatabaseJWTRegistry:
    def test_interface_matches(self):
        assert verifyClass(IJWTRegistry, DatabaseJWTRegistry)

    def test_create_service(self, db_request):
        service = DatabaseJWTRegistry.create_service(None, db_request)

        assert isinstance(service, DatabaseJWTRegistry)
        assert service.db is db_request.db

    def test_register(self, jwt_registry, db_session, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        first = jwt_registry.register(expires_at)
        second = jwt_registry.register(expires_at)

        assert isinstance(first, UUID)
        assert first.version == second.version == 7
        assert first != second
        assert db_session.get(IssuedJWT, first).expires_at == expires_at
        assert jwt_registry.is_active(first)
        assert jwt_registry.is_active(second)

    def test_register_normalizes_timezone(self, jwt_registry, db_session, clock):
        expires_at = (datetime.now(UTC) + timedelta(minutes=5)).astimezone(
            timezone(timedelta(hours=5))
        )
        token_id = jwt_registry.register(expires_at)

        token = db_session.get(IssuedJWT, token_id)
        assert token.expires_at == expires_at
        assert token.expires_at.utcoffset() == timedelta(0)

    def test_register_requires_timezone(self, jwt_registry):
        with pytest.raises(ValueError, match="timezone-aware"):
            jwt_registry.register(datetime(2026, 10, 22))

    @pytest.mark.parametrize("seconds", [-1, 0])
    def test_register_requires_future_expiry(self, jwt_registry, clock, seconds):
        with pytest.raises(ValueError, match="in the future"):
            jwt_registry.register(datetime.now(UTC) + timedelta(seconds=seconds))

    def test_register_does_not_overwrite(self, jwt_registry, db_session, clock, mocker):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        token_id = jwt_registry.register(expires_at)
        db_session.flush()
        mocker.patch("warehouse.jwt.services.uuid7", return_value=token_id)

        transaction = db_session.begin_nested()
        jwt_registry.register(expires_at + timedelta(minutes=1))
        with pytest.raises(UniqueViolation):
            db_session.flush()
        transaction.rollback()

        assert db_session.get(IssuedJWT, token_id).expires_at == expires_at

    def test_register_can_be_rolled_back(self, jwt_registry, db_session, clock):
        transaction = db_session.begin_nested()
        token_id = jwt_registry.register(datetime.now(UTC) + timedelta(minutes=5))
        assert jwt_registry.is_active(token_id)
        transaction.rollback()

        assert not jwt_registry.is_active(token_id)

    def test_missing_is_inactive(self, jwt_registry):
        assert not jwt_registry.is_active(uuid7())

    @pytest.mark.parametrize(
        ("elapsed", "active"), [(299.999999, True), (300, False), (301, False)]
    )
    def test_expiry_without_cleanup(
        self, jwt_registry, db_session, clock, elapsed, active
    ):
        token_id = jwt_registry.register(datetime.now(UTC) + timedelta(minutes=5))
        clock.tick(timedelta(seconds=elapsed))

        assert jwt_registry.is_active(token_id) is active
        assert db_session.get(IssuedJWT, token_id) is not None

    def test_revoke(self, jwt_registry, db_session, clock):
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        token_id = jwt_registry.register(expires_at)
        other_id = jwt_registry.register(expires_at)
        assert jwt_registry.is_active(token_id)

        jwt_registry.revoke(token_id)
        jwt_registry.revoke(token_id)
        jwt_registry.revoke(uuid7())

        assert not jwt_registry.is_active(token_id)
        assert db_session.get(IssuedJWT, token_id) is None
        assert jwt_registry.is_active(other_id)
        assert jwt_registry.register(expires_at) != token_id

    def test_revoke_can_be_rolled_back(self, jwt_registry, db_session, clock):
        token_id = jwt_registry.register(datetime.now(UTC) + timedelta(minutes=5))
        transaction = db_session.begin_nested()
        jwt_registry.revoke(token_id)
        assert not jwt_registry.is_active(token_id)
        transaction.rollback()

        assert jwt_registry.is_active(token_id)

    def test_sees_committed_revocation_with_cached_identity(self, app_config):
        engine = app_config.registry["sqlalchemy.engine"]
        with Session(engine) as writer, Session(engine) as reader:
            issuer = DatabaseJWTRegistry(writer)
            verifier = DatabaseJWTRegistry(reader)
            token_id = issuer.register(datetime.now(UTC) + timedelta(minutes=5))
            writer.commit()
            try:
                cached_token = reader.get(IssuedJWT, token_id)
                assert verifier.is_active(token_id)
                issuer.revoke(token_id)
                # The other transaction cannot see an uncommitted deletion.
                assert verifier.is_active(token_id)
                writer.commit()

                assert reader.get(IssuedJWT, token_id) is cached_token
                assert not verifier.is_active(token_id)
            finally:
                reader.rollback()
                issuer.revoke(token_id)
                writer.commit()

    def test_delete_expired(self, jwt_registry, db_session, clock):
        now = datetime.now(UTC)
        expired = jwt_registry.register(now + timedelta(seconds=1))
        boundary = jwt_registry.register(now + timedelta(seconds=2))
        active = jwt_registry.register(now + timedelta(seconds=3))
        clock.tick(timedelta(seconds=2))

        assert jwt_registry.delete_expired() == 2
        assert db_session.get(IssuedJWT, expired) is None
        assert db_session.get(IssuedJWT, boundary) is None
        assert jwt_registry.is_active(active)
        assert jwt_registry.delete_expired() == 0

    @pytest.mark.parametrize(
        ("method", "db_method", "args"),
        [
            ("is_active", "scalar", (uuid7(),)),
            ("revoke", "execute", (uuid7(),)),
            ("delete_expired", "execute", ()),
        ],
    )
    def test_database_errors_propagate(self, mocker, method, db_method, args):
        db_session = mocker.Mock(spec=["scalar", "execute"])
        getattr(db_session, db_method).side_effect = OperationalError(
            "statement", {}, Exception("database unavailable")
        )
        registry = DatabaseJWTRegistry(db_session)

        with pytest.raises(OperationalError):
            getattr(registry, method)(*args)
