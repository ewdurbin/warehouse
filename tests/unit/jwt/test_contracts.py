# SPDX-License-Identifier: Apache-2.0

from dataclasses import FrozenInstanceError

import pytest

from zope.interface.verify import verifyClass

from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.services import DisabledJWTVerifier


def test_verified_claims_are_immutable(verified):
    with pytest.raises(FrozenInstanceError):
        verified.audience = "different"
    with pytest.raises(FrozenInstanceError):
        verified.subject.id = None
    with pytest.raises(FrozenInstanceError):
        verified.authorization_details[0].resource.id = None


def test_disabled_verifier_contract():
    assert verifyClass(IJWTVerifier, DisabledJWTVerifier)
    verifier = DisabledJWTVerifier.create_service(None, None)
    for credential in ("", "invalid", "header.payload.signature"):
        assert verifier.verify(credential) is None
