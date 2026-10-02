# SPDX-License-Identifier: Apache-2.0

import types

import pytest

from pyramid import testing
from pyramid.request import Request, apply_request_extensions
from zope.interface.verify import verifyClass

from warehouse.accounts.jwt import JWTSecurityPolicy
from warehouse.api.interfaces import IJWTVerifier
from warehouse.api.services import DisabledJWTVerifier
from warehouse.authnz import Permissions
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import MultiSecurityPolicy


class TestDisabledJWTVerifier:
    def test_interface(self):
        assert verifyClass(IJWTVerifier, DisabledJWTVerifier)

    @pytest.mark.parametrize("token", ["", "garbage", "header.payload.signature"])
    def test_rejects_all_tokens(self, token):
        verifier = DisabledJWTVerifier()
        assert verifier.verify(token) is None
        assert not verifier.permits(token, None, None, Permissions.ProjectsUpload)

    def test_service_factory(self):
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service_factory(
                DisabledJWTVerifier.create_service, IJWTVerifier
            )
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/")
            request.registry = config.registry
            apply_request_extensions(request)
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"api-key"}, None)]
            )
            request.headers["Authorization"] = "Bearer header.payload.signature"
            verifier = request.find_service(IJWTVerifier, context=None)
            assert isinstance(verifier, DisabledJWTVerifier)
            assert verifier.verify("header.payload.signature") is None
            assert request.identity is None
            assert not request.has_permission(
                Permissions.ProjectsUpload, types.SimpleNamespace()
            )
