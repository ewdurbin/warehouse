# SPDX-License-Identifier: Apache-2.0

from pyramid.interfaces import ISecurityPolicy

from warehouse.accounts.security_policy import (
    BasicAuthSecurityPolicy,
    SessionSecurityPolicy,
)
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.macaroons.security_policy import MacaroonSecurityPolicy
from warehouse.utils.security_policy import MultiSecurityPolicy


def test_includeme(pyramid_config):
    pyramid_config.include("warehouse.authnz.security_policy")
    pyramid_config.commit()

    policy = pyramid_config.registry.getUtility(ISecurityPolicy)
    assert isinstance(policy, MultiSecurityPolicy)
    assert [type(p) for p in policy._policies] == [
        SessionSecurityPolicy,
        BasicAuthSecurityPolicy,
        MacaroonSecurityPolicy,
        JWTSecurityPolicy,
    ]
