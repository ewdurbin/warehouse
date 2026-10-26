# SPDX-License-Identifier: Apache-2.0

import types

import pytest

from pyramid import testing
from pyramid.request import Request, apply_request_extensions

from tests.common.jwt import UPLOAD_AUDIENCE
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.predicates import AuthMethodsPredicate, JWTAudiencePredicate


class TestWarehouseJWTVerifierFactory:
    @pytest.mark.parametrize("enabled", [False, True])
    def test_fixed_audience_ignores_request_metadata(
        self, jwt_settings, claims, sign, clock, enabled, mocker
    ):
        if not enabled:
            del jwt_settings["warehouse.jwt.verification_keys"]
        with testing.testConfig(settings=jwt_settings) as config:
            config.include("pyramid_services")
            config.add_directive("add_periodic_task", mocker.Mock())
            config.include("warehouse.jwt")
            config.commit()

            def make_request(audience):
                request = Request.blank("/")
                request.registry = config.registry
                if audience is not None:
                    request.matched_route = types.SimpleNamespace(
                        predicates=[
                            AuthMethodsPredicate({"jwt"}, None),
                            JWTAudiencePredicate(audience, None),
                        ]
                    )
                apply_request_extensions(request)
                return request

            verifier = make_request("api").find_service(
                IJWTVerifier, context=None, name="upload"
            )
            assert verifier.verify(sign()) is None
            claims["aud"] = UPLOAD_AUDIENCE
            assert (verifier.verify(sign()) is not None) is enabled

            unrouted = make_request(None).find_service(
                IJWTVerifier, context=None, name="upload"
            )
            assert (unrouted.verify(sign()) is not None) is enabled
            if enabled:
                routed = make_request("upload").find_service(IJWTVerifier, context=None)
                assert routed is verifier
