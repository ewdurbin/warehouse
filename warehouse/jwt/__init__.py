# SPDX-License-Identifier: Apache-2.0

from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import DatabaseJWTRegistry, DisabledJWTVerifier


def includeme(config):
    config.register_service_factory(DisabledJWTVerifier.create_service, IJWTVerifier)
    config.register_service_factory(DatabaseJWTRegistry.create_service, IJWTRegistry)
