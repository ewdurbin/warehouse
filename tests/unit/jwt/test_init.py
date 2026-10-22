# SPDX-License-Identifier: Apache-2.0


from warehouse.jwt import includeme
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTVerifier,
)


def test_includeme(mocker):
    config = mocker.Mock(
        spec=["register_service_factory", "add_periodic_task", "registry"]
    )
    config.registry.settings = {}

    includeme(config)

    assert config.register_service_factory.call_args_list == [
        mocker.call(DisabledJWTVerifier.create_service, IJWTVerifier),
        mocker.call(DatabaseJWTRegistry.create_service, IJWTRegistry),
    ]
