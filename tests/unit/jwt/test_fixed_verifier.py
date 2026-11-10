# SPDX-License-Identifier: Apache-2.0

from tests.common.jwt import UPLOAD_AUDIENCE
from warehouse.jwt.interfaces import IJWTVerifier


def test_named_upload_verifier_on_burn_route(make_request, claims, sign):
    upload_token = sign(claims | {"aud": UPLOAD_AUDIENCE})
    request = make_request("/_/oidc/burn-token", upload_token)
    assert request.matched_route.name == "oidc.burn_token"

    routed_verifier = request.find_service(IJWTVerifier, context=None)
    assert routed_verifier.verify(upload_token) is None

    upload_verifier = request.find_service(IJWTVerifier, context=None, name="upload")
    assert upload_verifier.verify(upload_token) is not None
    assert upload_verifier.verify(sign()) is None
