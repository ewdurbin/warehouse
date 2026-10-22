# SPDX-License-Identifier: Apache-2.0

import types

import pytest

from pyramid import testing

from tests.common.jwt import (
    UPLOAD_AUDIENCE,
)
from warehouse.jwt.services import (
    jwt_verifier_factory,
)
from warehouse.predicates import AuthMethodsPredicate, JWTAudiencePredicate


class TestWarehouseJWTVerifierFactory:
    @pytest.mark.parametrize("enabled", [False, True])
    def test_fixed_audience_ignores_request_metadata(
        self, jwt_settings, claims, sign, clock, enabled
    ):
        jwt_settings["warehouse.jwt.enabled"] = enabled
        factory = jwt_verifier_factory(jwt_settings, audience="upload")
        request = testing.DummyRequest()
        request.matched_route = types.SimpleNamespace(
            predicates=[
                AuthMethodsPredicate({"jwt"}, None),
                JWTAudiencePredicate("api", None),
            ]
        )
        verifier = factory(None, request)
        assert (
            verifier.verify(sign()) is None
        )  # API audience cannot burn an upload token.
        claims["aud"] = UPLOAD_AUDIENCE
        assert (verifier.verify(sign()) is not None) is enabled
        request.matched_route = None
        assert (factory(None, request).verify(sign()) is not None) is enabled
