# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab

from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    jwt_issuer_factory,
    jwt_verifier_factory,
)
from warehouse.jwt.tasks import delete_expired_jwts


def includeme(config):
    # JWT authentication remains disabled unless explicitly configured otherwise.
    config.register_service_factory(
        jwt_verifier_factory(config.registry.settings), IJWTVerifier
    )
    config.register_service_factory(DatabaseJWTRegistry.create_service, IJWTRegistry)
    config.register_service_factory(
        jwt_issuer_factory(config.registry.settings), IJWTIssuer
    )
    config.add_periodic_task(crontab(minute=0), delete_expired_jwts)
