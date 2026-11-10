# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime, timedelta

from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS
from warehouse.jwt.tasks import delete_expired_jwts


def test_delete_expired_jwts(db_request, jwt_registry, db_session, metrics, clock):
    lifetime = timedelta(seconds=MAX_LIFETIME_SECONDS)
    expires_at = datetime.now(UTC) + lifetime
    eligible = jwt_registry.register(expires_at)
    clock.tick(timedelta(seconds=1))
    recently_expired = jwt_registry.register(datetime.now(UTC) + lifetime)

    clock.move_to(expires_at + lifetime)
    active = jwt_registry.register(datetime.now(UTC) + lifetime)
    delete_expired_jwts(db_request)

    assert db_session.get(IssuedJWT, eligible) is None
    assert db_session.get(IssuedJWT, recently_expired) is not None
    assert not jwt_registry.is_active(recently_expired)
    assert jwt_registry.is_active(active)
    metrics.gauge.assert_called_once_with("warehouse.jwt.expired_tokens_deleted", 1)
