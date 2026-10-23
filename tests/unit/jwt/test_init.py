# SPDX-License-Identifier: Apache-2.0


from celery.schedules import crontab

from warehouse.jwt import includeme
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTVerifier,
)
from warehouse.jwt.tasks import delete_expired_jwts


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
    config.add_periodic_task.assert_called_once_with(
        crontab(minute=0), delete_expired_jwts
    )
