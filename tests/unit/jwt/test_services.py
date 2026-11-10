# SPDX-License-Identifier: Apache-2.0

import pytest

from zope.interface.verify import verifyClass

from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.services import DisabledJWTVerifier


class TestDisabledJWTVerifier:
    def test_interface(self):
        assert verifyClass(IJWTVerifier, DisabledJWTVerifier)

    @pytest.mark.parametrize("token", ["", "garbage", "header.payload.signature"])
    def test_rejects_all_tokens(self, token):
        verifier = DisabledJWTVerifier()
        assert verifier.verify(token) is None
