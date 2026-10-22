# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab

from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTSigner, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTIssuer,
    jwt_issuer_factory,
    jwt_verifier_factory,
)
from warehouse.jwt.signing import KMSJWTSignerService
from warehouse.jwt.tasks import delete_expired_jwts


def includeme(config):
    # JWT authentication remains disabled unless explicitly configured otherwise.
    config.register_service_factory(
        jwt_verifier_factory(config.registry.settings), IJWTVerifier
    )
    config.register_service_factory(DatabaseJWTRegistry.create_service, IJWTRegistry)
    issuer_factory = jwt_issuer_factory(config.registry.settings)
    if issuer_factory != DisabledJWTIssuer.create_service:
        config.register_service(
            KMSJWTSignerService.from_settings(config.registry.settings), IJWTSigner
        )
    config.register_service_factory(issuer_factory, IJWTIssuer)
    config.add_periodic_task(crontab(minute=0), delete_expired_jwts)
