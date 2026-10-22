# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab

from warehouse.jwt import includeme
from warehouse.jwt.interfaces import IJWTRegistry
from warehouse.jwt.services import DatabaseJWTRegistry
from warehouse.jwt.tasks import delete_expired_jwts


def test_includeme(mocker):
    config = mocker.Mock(spec=["register_service_factory", "add_periodic_task"])

    includeme(config)

    config.register_service_factory.assert_called_once_with(
        DatabaseJWTRegistry.create_service, IJWTRegistry
    )
    config.add_periodic_task.assert_called_once_with(
        crontab(minute=0), delete_expired_jwts
    )
