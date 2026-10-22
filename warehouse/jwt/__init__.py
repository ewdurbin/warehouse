# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab

from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTSigner, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTIssuer,
    DisabledJWTVerifier,
    jwt_issuer_factory,
    jwt_verifier_factory,
)
from warehouse.jwt.signing import KMSJWTSignerService
from warehouse.jwt.tasks import delete_expired_jwts


def includeme(config):
    settings = config.registry.settings
    verifier_factory = jwt_verifier_factory(settings)
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

    if (
        "warehouse.jwt.kms_key_id" in settings
        or "warehouse.jwt.signing_key_id" in settings
    ):
        issuer_factory = jwt_issuer_factory(settings)
        config.register_service(KMSJWTSignerService.from_settings(settings), IJWTSigner)
        config.register_service_factory(issuer_factory, IJWTIssuer)
    else:
        config.register_service(DisabledJWTIssuer(), IJWTIssuer)

    config.add_periodic_task(crontab(minute=0), delete_expired_jwts)
