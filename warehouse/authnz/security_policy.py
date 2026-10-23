# SPDX-License-Identifier: Apache-2.0

from warehouse.accounts.security_policy import (
    BasicAuthSecurityPolicy,
    SessionSecurityPolicy,
)
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.macaroons.security_policy import MacaroonSecurityPolicy
from warehouse.utils.security_policy import MultiSecurityPolicy


def includeme(config):
    config.set_security_policy(
        MultiSecurityPolicy(
            [
                SessionSecurityPolicy(),
                BasicAuthSecurityPolicy(),
                MacaroonSecurityPolicy(),
                JWTSecurityPolicy(),
            ]
        )
    )
