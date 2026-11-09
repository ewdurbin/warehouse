# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete

from warehouse import tasks
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS

if TYPE_CHECKING:
    from pyramid.request import Request


@tasks.task(ignore_result=True, acks_late=True)
def delete_expired_jwts(request: Request) -> None:
    """Delete JWT rows at least one maximum token lifetime past expiration."""
    cutoff = datetime.now(UTC) - timedelta(seconds=MAX_LIFETIME_SECONDS)
    result = request.db.execute(
        delete(IssuedJWT)
        .where(IssuedJWT.expires_at <= cutoff)
        .execution_options(synchronize_session=False)
    )
    request.metrics.gauge("warehouse.jwt.expired_tokens_deleted", result.rowcount)
