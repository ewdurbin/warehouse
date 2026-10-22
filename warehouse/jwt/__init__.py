# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab

from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTVerifier,
    jwt_issuer_factory,
    jwt_verifier_factory,
)
from warehouse.jwt.tasks import delete_expired_jwts


def includeme(config):
    # JWT authentication remains disabled unless explicitly configured otherwise.
    verifier_factory = jwt_verifier_factory(config.registry.settings)
    upload_verifier_factory = (
        verifier_factory
        if verifier_factory == DisabledJWTVerifier.create_service
        else verifier_factory.for_audience("upload")
    )
    config.register_service_factory(verifier_factory, IJWTVerifier)
    config.register_service_factory(
        upload_verifier_factory, IJWTVerifier, name="upload"
    )
    config.register_service_factory(DatabaseJWTRegistry.create_service, IJWTRegistry)
    config.register_service_factory(
        jwt_issuer_factory(config.registry.settings), IJWTIssuer
    )
    config.add_periodic_task(crontab(minute=0), delete_expired_jwts)
