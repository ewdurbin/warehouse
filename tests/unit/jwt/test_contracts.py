# SPDX-License-Identifier: Apache-2.0

from dataclasses import FrozenInstanceError

import pytest


def test_verified_claims_are_immutable(verified):
    with pytest.raises(FrozenInstanceError):
        verified.audience = "different"
    with pytest.raises(FrozenInstanceError):
        verified.subject.id = None
    with pytest.raises(FrozenInstanceError):
        verified.authorization_details[0].resource.id = None
