# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab

from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import DatabaseJWTRegistry, DisabledJWTVerifier
from warehouse.jwt.tasks import delete_expired_jwts


def includeme(config):
    config.register_service_factory(DisabledJWTVerifier.create_service, IJWTVerifier)
    config.register_service_factory(DatabaseJWTRegistry.create_service, IJWTRegistry)
    config.add_periodic_task(crontab(minute=0), delete_expired_jwts)
