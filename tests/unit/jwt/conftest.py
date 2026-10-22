# SPDX-License-Identifier: Apache-2.0

import types

from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from freezegun import freeze_time
from pyramid.authorization import Authenticated

from tests.common.jwt import API_AUDIENCE, ISSUER, JTI, NOW, PROJECT_ID, USER_ID
from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
    SubjectKind,
    SubjectRef,
    VerifiedJWT,
)
from warehouse.jwt.verifier import WarehouseJWTVerifier
from warehouse.packaging.models import Project


@pytest.fixture
def verified():
    project = ResourceRef(
        ResourceKind.PROJECT, UUID("95ea64e2-764c-4320-a4e5-991df49f261f")
    )
    return VerifiedJWT(
        jti=UUID("0199c0f2-4b00-7000-8000-000000000001"),
        subject=SubjectRef(
            SubjectKind.USER, UUID("ddf9597e-dda1-45a2-b026-3a090ad7c4b2")
        ),
        issuer="https://warehouse.example",
        audience="https://warehouse.example/api",
        issued_at=datetime.fromtimestamp(2_000_000_000, UTC),
        expires_at=datetime.fromtimestamp(2_000_000_300, UTC),
        authorization_details=(
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,), project
            ),
            AuthorizationDetail(AuthorizationType.WAREHOUSE, (Permissions.APIEcho,)),
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.APIObservationsAdd,), project
            ),
        ),
    )


@pytest.fixture(scope="module")
def signing_keys():
    return [
        rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)
    ]


@pytest.fixture
def clock():
    with freeze_time(datetime.fromtimestamp(NOW, UTC), ignore=["_pytest"]) as clock:
        yield clock


@pytest.fixture
def claims():
    return {
        "iss": ISSUER,
        "aud": API_AUDIENCE,
        "sub": USER_ID,
        "subject_kind": "user",
        "jti": JTI,
        "iat": NOW - 60,
        "exp": NOW + 240,
        "authorization_details": [
            {
                "type": "warehouse",
                "actions": ["projects:upload"],
                "identifier": f"project:{PROJECT_ID}",
            },
            {"type": "warehouse", "actions": ["api:echo"]},
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{PROJECT_ID}",
            },
        ],
    }


@pytest.fixture
def headers():
    return {"alg": "RS256", "typ": "pypi-access+jwt", "kid": "current"}


@pytest.fixture
def sign(signing_keys, claims, headers):
    def sign(payload=None, *, header=None, key=None):
        return jwt.encode(
            claims if payload is None else payload,
            signing_keys[0] if key is None else key,
            algorithm="RS256",
            headers=headers if header is None else header,
        )

    return sign


@pytest.fixture
def expected_audience():
    return API_AUDIENCE


@pytest.fixture
def verifier(signing_keys, clock, expected_audience):
    return WarehouseJWTVerifier(
        issuer=ISSUER,
        audience=expected_audience,
        keys={"current": signing_keys[0].public_key()},
    )


@pytest.fixture
def registered_jti(jwt_registry, clock, claims):
    token_id = jwt_registry.register(datetime.fromtimestamp(claims["exp"], UTC))
    claims["jti"] = str(token_id)
    return token_id


@pytest.fixture
def user():
    return types.SimpleNamespace(
        id=UUID(USER_ID), __principals__=lambda: [Authenticated, f"user:{USER_ID}"]
    )


@pytest.fixture
def project(mocker):
    return mocker.Mock(spec=Project, id=UUID(PROJECT_ID))
