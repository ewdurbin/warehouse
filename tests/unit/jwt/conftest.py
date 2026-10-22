# SPDX-License-Identifier: Apache-2.0

import types

from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from freezegun import freeze_time
from pyramid import testing
from pyramid.authorization import Authenticated
from pyramid.interfaces import IRoutesMapper
from pyramid.request import Request, apply_request_extensions

from tests.common.jwt import (
    API_AUDIENCE,
    ISSUER,
    JTI,
    NOW,
    PROJECT_ID,
    UPLOAD_AUDIENCE,
    USER_ID,
)
from warehouse.accounts.interfaces import IUserService
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
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.jwt.verifier import (
    WarehouseJWTVerifier,
)
from warehouse.packaging.models import Project
from warehouse.routes import includeme as include_routes
from warehouse.utils.security_policy import MultiSecurityPolicy


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


@pytest.fixture
def issue_args(verified):
    return {
        "subject": verified.subject,
        "audience": "upload",
        "authorization_details": verified.authorization_details,
    }


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


@pytest.fixture
def jwt_settings(signing_keys):
    return {
        "warehouse.jwt.enabled": True,
        "warehouse.jwt.issuer": ISSUER,
        "warehouse.jwt.upload_audience": UPLOAD_AUDIENCE,
        "warehouse.jwt.api_audience": API_AUDIENCE,
        "warehouse.jwt.verification_keys": {
            kid: key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
            for kid, key in zip(("current", "previous"), signing_keys, strict=True)
        },
    }


@pytest.fixture
def jwt_enabled():
    return True


@pytest.fixture
def make_request(
    jwt_settings, jwt_enabled, user_service, mocker, clock, registered_jti, db_session
):
    jwt_settings.pop("warehouse.jwt.enabled")
    if jwt_enabled is not None:
        jwt_settings["warehouse.jwt.enabled"] = jwt_enabled
    jwt_settings.update(
        {
            "docs.url": "https://docs.example",
            "files.url": "https://files.example/{path}",
        }
    )
    with testing.testConfig(settings=jwt_settings) as config:
        config.include("pyramid_services")
        config.include("warehouse.predicates")
        config.include("warehouse.legacy.action_routing")
        config.include("warehouse.forklift")
        # Install the application's actual add_route declarations without
        # unrelated redirect/template/XML-RPC view configuration.
        route_config = mocker.Mock()
        route_config.get_settings.return_value = config.get_settings()
        route_config.registry = config.registry
        route_config.add_route = config.add_route
        include_routes(route_config)
        for audience_name in ("api", "upload"):
            config.add_route(
                f"new-endpoint.{audience_name}",
                f"/audience-test/{audience_name}",
                auth_methods={"jwt"},
                jwt_audience=audience_name,
            )
        config.add_directive("add_periodic_task", mocker.Mock())
        config.include("warehouse.jwt")
        config.register_service(user_service, IUserService)
        config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
        config.commit()
        mapper = config.registry.getUtility(IRoutesMapper)

        def make_request(path, token):
            request = Request.blank(path)
            request.registry = config.registry
            apply_request_extensions(request)
            request.db = db_session
            request.headers["Authorization"] = f"Bearer {token}"
            match = mapper(request)
            request.matched_route = match["route"]
            request.matchdict = match["match"]
            return request

        yield make_request
