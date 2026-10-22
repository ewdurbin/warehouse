# SPDX-License-Identifier: Apache-2.0

from warehouse import tasks
from warehouse.jwt.interfaces import IJWTRegistry


@tasks.task(ignore_result=True, acks_late=True)
def delete_expired_jwts(request):
    registry = request.find_service(IJWTRegistry, context=None)
    deleted = registry.delete_expired()
    request.metrics.gauge("warehouse.jwt.expired_tokens_deleted", deleted)
