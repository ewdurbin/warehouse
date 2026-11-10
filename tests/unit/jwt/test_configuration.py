# SPDX-License-Identifier: Apache-2.0

import pytest

from cryptography.hazmat.primitives import serialization
from pyramid import testing
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import IRoutesMapper

from tests.common.jwt import UPLOAD_AUDIENCE
from warehouse.jwt.services import WarehouseJWTVerifierFactory


@pytest.mark.parametrize(
    ("setting", "message"),
    [
        ("issuer", "A JWT issuer is required"),
        ("upload_audience", "A JWT audience is required"),
        ("api_audience", "A JWT audience is required"),
    ],
)
def test_missing_setting(jwt_settings, setting, message):
    del jwt_settings[f"warehouse.jwt.{setting}"]
    with pytest.raises(ConfigurationError, match=message):
        WarehouseJWTVerifierFactory(jwt_settings)


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("api_audience", UPLOAD_AUDIENCE, "audiences must be distinct"),
        ("verification_keys", {}, "must map key IDs to PEM public keys"),
        ("verification_keys", {"current": "not PEM"}, "Invalid JWT PEM public key"),
    ],
)
def test_invalid_setting(jwt_settings, setting, value, message):
    jwt_settings[f"warehouse.jwt.{setting}"] = value
    with pytest.raises(ConfigurationError, match=message):
        WarehouseJWTVerifierFactory(jwt_settings)


def test_private_key_is_rejected(jwt_settings, signing_keys):
    jwt_settings["warehouse.jwt.verification_keys"]["current"] = (
        signing_keys[0]
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(ConfigurationError, match="Invalid JWT PEM public key"):
        WarehouseJWTVerifierFactory(jwt_settings)


@pytest.mark.parametrize(
    ("route_options", "accepted"),
    [
        pytest.param(None, False, id="no-matched-route"),
        pytest.param({"auth_methods": {"jwt"}}, False, id="missing-audience"),
        pytest.param({"jwt_audience": "api"}, False, id="missing-auth-methods"),
        pytest.param(
            {"jwt_audience": "api", "auth_methods": {"api-key"}},
            False,
            id="different-auth-method",
        ),
        pytest.param(
            {"jwt_audience": "api", "auth_methods": {"jwt"}}, True, id="jwt-route"
        ),
    ],
)
def test_route_must_declare_audience_and_jwt_method(
    jwt_settings, clock, sign, route_options, accepted
):
    factory = WarehouseJWTVerifierFactory(jwt_settings)
    request = testing.DummyRequest(matched_route=None)

    if route_options is not None:
        with testing.testConfig() as config:
            config.include("warehouse.predicates")
            config.add_route("new-endpoint", "/", **route_options)
            mapper = config.registry.getUtility(IRoutesMapper)
            request.matched_route = mapper.get_route("new-endpoint")

    assert (factory(None, request).verify(sign()) is not None) == accepted
