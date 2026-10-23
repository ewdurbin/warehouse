# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime, timedelta

from freezegun import freeze_time

from warehouse.jwt.profile import MAX_LIFETIME_SECONDS
from warehouse.jwt.tasks import delete_expired_jwts


def test_delete_expired_jwts(db_request, jwt_registry, metrics):
    with freeze_time("2026-10-22 00:00:00+00:00", ignore=["_pytest"]) as clock:
        now = datetime.now(UTC)
        expired = jwt_registry.register(now + timedelta(seconds=1))
        clock.tick(timedelta(seconds=MAX_LIFETIME_SECONDS + 1))
        active = jwt_registry.register(datetime.now(UTC) + timedelta(seconds=1))

        delete_expired_jwts(db_request)

        metrics.gauge.assert_called_once_with("warehouse.jwt.expired_tokens_deleted", 1)
        assert not jwt_registry.is_active(expired)
        assert jwt_registry.is_active(active)
