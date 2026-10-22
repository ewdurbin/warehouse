# SPDX-License-Identifier: Apache-2.0

from celery.schedules import crontab
from pyramid.request import Request, apply_request_extensions

from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTVerifier
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTIssuer,
    DisabledJWTVerifier,
)
from warehouse.jwt.tasks import delete_expired_jwts


def test_default_services_and_cleanup_schedule(app_config, db_session):
    request = Request.blank("/")
    request.registry = app_config.registry
    request.db = db_session
    apply_request_extensions(request)

    registry = request.find_service(IJWTRegistry, context=None)
    assert isinstance(registry, DatabaseJWTRegistry)
    assert registry.db is db_session
    assert isinstance(
        request.find_service(IJWTVerifier, context=None), DisabledJWTVerifier
    )
    assert isinstance(
        request.find_service(IJWTVerifier, name="upload", context=None),
        DisabledJWTVerifier,
    )
    assert isinstance(request.find_service(IJWTIssuer, context=None), DisabledJWTIssuer)

    task_name = app_config.task(delete_expired_jwts).name
    schedule = app_config.registry["celery.app"].conf.beat_schedule
    assert any(
        entry["task"] == task_name and entry["schedule"] == crontab(minute=0)
        for entry in schedule.values()
    )
