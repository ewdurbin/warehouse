# SPDX-License-Identifier: Apache-2.0

import types

from uuid import UUID

import pytest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pyramid import testing
from pyramid.exceptions import ConfigurationError

from tests.common.jwt import (
    API_AUDIENCE,
    ISSUER,
    UPLOAD_AUDIENCE,
    USER_ID,
)
from warehouse.jwt.claims import (
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.services import (
    DisabledJWTVerifier,
    jwt_verifier_factory,
)
from warehouse.jwt.verifier import (
    WarehouseJWTVerifierFactory,
)
from warehouse.predicates import AuthMethodsPredicate, JWTAudiencePredicate


class TestWarehouseJWTVerifierFactory:
    def test_no_verification_keys(self, jwt_settings):
        del jwt_settings["warehouse.jwt.verification_keys"]
        assert jwt_verifier_factory(jwt_settings) == DisabledJWTVerifier.create_service

    @pytest.mark.parametrize(
        "setting",
        ["issuer", "upload_audience", "api_audience"],
    )
    def test_missing_setting(self, jwt_settings, setting):
        del jwt_settings[f"warehouse.jwt.{setting}"]
        with pytest.raises(ConfigurationError, match=r"JWT|warehouse\.jwt"):
            jwt_verifier_factory(jwt_settings)

    @pytest.mark.parametrize(
        ("setting", "value"),
        [
            ("issuer", ""),
            ("issuer", [ISSUER]),
            ("upload_audience", ""),
            ("api_audience", ""),
            ("api_audience", [API_AUDIENCE]),
            ("api_audience", UPLOAD_AUDIENCE),
            ("verification_keys", {}),
            ("verification_keys", None),
            ("verification_keys", []),
            ("verification_keys", "not a mapping"),
            ("verification_keys", {"current": None}),
            ("verification_keys", {"current": "not PEM"}),
        ],
    )
    def test_invalid_setting(self, jwt_settings, setting, value):
        jwt_settings[f"warehouse.jwt.{setting}"] = value
        with pytest.raises(ConfigurationError, match=r"JWT|warehouse\.jwt"):
            jwt_verifier_factory(jwt_settings)

    @pytest.mark.parametrize("kid", ["", 1])
    def test_invalid_key_id(self, jwt_settings, kid):
        keys = jwt_settings["warehouse.jwt.verification_keys"]
        jwt_settings["warehouse.jwt.verification_keys"] = {kid: keys["current"]}
        with pytest.raises(ConfigurationError, match="key IDs"):
            jwt_verifier_factory(jwt_settings)

    def test_private_key(self, jwt_settings, signing_keys):
        jwt_settings["warehouse.jwt.verification_keys"]["current"] = (
            signing_keys[0]
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        with pytest.raises(ConfigurationError, match="PEM public key"):
            jwt_verifier_factory(jwt_settings)

    @pytest.mark.parametrize("kind", ["ec", "weak-rsa"])
    def test_unsuitable_public_key(self, jwt_settings, kind):
        if kind == "ec":
            key = ec.generate_private_key(ec.SECP256R1())
        else:
            # Deliberately insecure: startup must reject this key.
            key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
        jwt_settings["warehouse.jwt.verification_keys"]["current"] = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        with pytest.raises(ConfigurationError, match="RSA public keys >= 2048 bits"):
            jwt_verifier_factory(jwt_settings)

    def test_unsupported_key_algorithm(self, jwt_settings, mocker):
        mocker.patch(
            "warehouse.jwt.verifier.load_pem_public_key",
            side_effect=UnsupportedAlgorithm("Unsupported key algorithm"),
        )
        with pytest.raises(ConfigurationError, match="PEM public key"):
            jwt_verifier_factory(jwt_settings)

    def test_loads_keys_once(self, jwt_settings, mocker, clock, sign):
        load = mocker.patch(
            "warehouse.jwt.verifier.load_pem_public_key",
            wraps=serialization.load_pem_public_key,
        )
        factory = jwt_verifier_factory(jwt_settings)
        assert isinstance(factory, WarehouseJWTVerifierFactory)
        assert load.call_count == 2
        request = testing.DummyRequest()
        request.matched_route = types.SimpleNamespace(
            name="api.echo",
            predicates=[
                AuthMethodsPredicate({"jwt"}, None),
                JWTAudiencePredicate("api", None),
            ],
        )
        # Configuration is snapshotted at startup, never read from the request.
        jwt_settings["warehouse.jwt.verification_keys"].clear()
        jwt_settings["warehouse.jwt.api_audience"] = UPLOAD_AUDIENCE
        verifier = factory(None, request)
        assert factory(None, request) is verifier
        assert verifier.verify(sign()).subject == SubjectRef(
            SubjectKind.USER, UUID(USER_ID)
        )
        assert load.call_count == 2

    @pytest.mark.parametrize(
        "route_name",
        [
            None,
            "api.echo",
            "forklift.legacy.file_upload",
            "api.unknown",
            "api.echo.attacker",
            "forklift.legacy.submit",
            "manage.account",
        ],
    )
    def test_missing_audience(self, jwt_settings, route_name, clock, sign):
        request = testing.DummyRequest()
        request.matched_route = (
            types.SimpleNamespace(
                name=route_name, predicates=[AuthMethodsPredicate({"jwt"}, None)]
            )
            if route_name is not None
            else None
        )
        verifier = jwt_verifier_factory(jwt_settings)(None, request)
        assert isinstance(verifier, DisabledJWTVerifier)
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize("methods", [None, set(), {"macaroon"}, {"api-key"}])
    def test_route_requires_jwt_opt_in(self, jwt_settings, methods):
        request = testing.DummyRequest()
        request.matched_route = types.SimpleNamespace(
            name="api.echo",
            predicates=[JWTAudiencePredicate("api", None)]
            + ([] if methods is None else [AuthMethodsPredicate(methods, None)]),
        )
        assert isinstance(
            jwt_verifier_factory(jwt_settings)(None, request), DisabledJWTVerifier
        )
