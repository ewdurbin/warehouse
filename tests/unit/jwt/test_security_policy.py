# SPDX-License-Identifier: Apache-2.0

import pytest

from pyramid.interfaces import ISecurityPolicy
from pyramid.request import Request
from pyramid.response import Response
from zope.interface.verify import verifyClass

from warehouse.jwt.security_policy import JWTSecurityPolicy, _extract_http_jwt


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("Bearer", None),
        ("Bearer one two", None),
        ("Bearer pypi-token", None),
        ("bEaReR   header.payload.signature", "header.payload.signature"),
    ],
)
def test_extract_http_jwt(header, expected):
    request = Request.blank("/")
    if header is not None:
        request.headers["Authorization"] = header

    assert _extract_http_jwt(request) == expected


def test_security_policy_interface():
    assert verifyClass(ISecurityPolicy, JWTSecurityPolicy)


def test_varies_on_authorization():
    request = Request.blank("/")
    request.matched_route = None
    response = Response()
    response.vary = ("Accept",)

    assert JWTSecurityPolicy().identity(request) is None
    request._process_response_callbacks(response)

    assert set(response.vary) == {"Accept", "Authorization"}
