# SPDX-License-Identifier: Apache-2.0

import pytest
import sentry_sdk

from pyramid.config import Configurator
from sentry_sdk.integrations.pyramid import PyramidIntegration
from sentry_sdk.transport import Transport
from sentry_sdk.utils import iter_event_frames
from webtest import TestApp

from warehouse import sentry
from warehouse.oidc.views import burn_oidc_issued_token


def test_sentry_request_method(pyramid_request, mocker):
    sentry_obj = mocker.sentinel.sentry_sdk
    pyramid_request.registry["sentry"] = sentry_obj

    assert sentry._sentry(pyramid_request) is sentry_obj


class TestSentryBeforeSend:
    @pytest.mark.parametrize(
        ("event", "hint"),
        [
            (
                {"message": "This is fine."},
                {"exc_info": (SystemExit, SystemExit(), "tracebk")},
            ),
            (
                {"message": "Worker (pid:35) was sent SIGINT!"},
                {},
            ),
            (
                {"message": "Worker (pid:1706) was sent code 131!"},
                {},
            ),
        ],
    )
    def test_ignore_exception(self, event, hint):
        assert sentry.before_send(event, hint) is None

    @pytest.mark.parametrize(
        ("event", "hint"),
        [
            (
                {"message": "This is fine."},
                {"exc_info": (ConnectionError, ConnectionError(), "tracebk")},
            ),
            ({"message": "This is fine."}, {"event_info": "This is a random event."}),
        ],
    )
    def test_report_event(self, event, hint):
        assert sentry.before_send(event, hint) is event


@pytest.mark.parametrize(
    "credential", ["pypi-synthetic-burn-token", "header.synthetic-burn-token.signature"]
)
def test_burn_error_reports_traceback_without_credential(credential):
    envelopes = []

    class RecordingTransport(Transport):
        def capture_envelope(self, envelope):
            envelopes.append(envelope)

    def unavailable_service(request, *args, **kwargs):
        raise RuntimeError("burn service unavailable")

    with Configurator() as config:
        config.add_route("oidc.burn_token", "/_/oidc/burn-token")
        config.add_view(burn_oidc_issued_token, route_name="oidc.burn_token")
        config.add_request_method(unavailable_service, "find_service")
        app = TestApp(config.make_wsgi_app())

    with (
        sentry_sdk.Client(
            transport=RecordingTransport(),
            integrations=[PyramidIntegration()],
            before_send=sentry.before_send,
        ) as client,
        sentry_sdk.isolation_scope() as scope,
    ):
        scope.set_client(client)
        with pytest.raises(RuntimeError, match="burn service unavailable"):
            app.post_json("/_/oidc/burn-token", {"token": credential})

    (envelope,) = envelopes
    event = envelope.get_event()
    assert event["transaction"] == "oidc.burn_token"
    assert "data" not in event["request"]
    frames = list(iter_event_frames(event))
    assert any(frame["function"] == "burn_oidc_issued_token" for frame in frames)
    assert all("vars" not in frame for frame in frames)
    assert credential.encode() not in envelope.serialize()


def test_includeme(pyramid_config, mocker):
    init_obj = mocker.patch.object(sentry_sdk, "init", return_value="1")
    pyramid_obj = mocker.patch("warehouse.sentry.PyramidIntegration", return_value="2")
    celery_obj = mocker.patch("warehouse.sentry.CeleryIntegration", return_value="3")
    sql_obj = mocker.patch("warehouse.sentry.SqlalchemyIntegration", return_value="4")
    log_obj = mocker.patch("warehouse.sentry.LoggingIntegration", return_value="5")
    add_request_method = mocker.patch.object(
        pyramid_config, "add_request_method", autospec=True
    )

    pyramid_config.registry.settings.update(
        {
            "warehouse.commit": "rand3rfgkn3424",
            "sentry.dsn": "test_dsn",
            "sentry.transport": "proxy_transport",
        }
    )

    sentry.includeme(pyramid_config)

    init_obj.assert_called_once_with(
        dsn="test_dsn",
        release="rand3rfgkn3424",
        transport="proxy_transport",
        before_send=sentry.before_send,
        attach_stacktrace=True,
        integrations=["2", "3", "4", "5"],
    )
    pyramid_obj.assert_called_once_with()
    celery_obj.assert_called_once_with()
    sql_obj.assert_called_once_with()
    log_obj.assert_called_once_with()
    assert pyramid_config.registry["sentry"] is sentry_sdk
    add_request_method.assert_called_once_with(
        sentry._sentry, name="sentry", reify=True
    )
