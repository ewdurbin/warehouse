# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime
from uuid import UUID

import pytest

from sqlalchemy.orm import Session

from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from tests.common.jwt import API_AUDIENCE, UPLOAD_AUDIENCE, USER_ID
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.services import DatabaseJWTRegistry
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.utils.security_policy import AuthenticationMethod

UPLOAD_PATH = "/legacy/?:action=file_upload"
ECHO_PATH = "/danger-api/echo"


@pytest.fixture
def user(db_session):
    return UserFactory(id=UUID(USER_ID), clear_pwd="password")


@pytest.mark.parametrize(
    ("path", "route_name", "audience"),
    [
        (UPLOAD_PATH, "forklift.legacy.file_upload", UPLOAD_AUDIENCE),
        (ECHO_PATH, "api.echo", API_AUDIENCE),
        (
            "/danger-api/projects/example/observations",
            "api.projects.observations",
            API_AUDIENCE,
        ),
    ],
)
def test_route_requires_matching_audience(
    make_request, sign, claims, user, path, route_name, audience
):
    request = make_request(path, sign({**claims, "aud": audience}))
    assert request.matched_route.name == route_name
    assert request.identity == UserContext(user, macaroon=None)
    assert request.authentication_method == AuthenticationMethod.JWT

    other_audience = UPLOAD_AUDIENCE if audience == API_AUDIENCE else API_AUDIENCE
    wrong_token = sign({**claims, "aud": other_audience})
    assert make_request(path, wrong_token).identity is None


def test_accepts_previous_key(make_request, sign, headers, signing_keys, user):
    token = sign(header={**headers, "kid": "previous"}, key=signing_keys[1])
    assert make_request(ECHO_PATH, token).identity == UserContext(user, macaroon=None)


@pytest.mark.parametrize("jwt_settings", [{}])
@pytest.mark.usefixtures("user")
def test_disabled_by_default(make_request, sign):
    assert make_request(ECHO_PATH, sign()).identity is None


@pytest.mark.usefixtures("user")
def test_request_fields_cannot_override_matched_route_audience(make_request, sign):
    request = make_request(UPLOAD_PATH, sign())
    assert request.matched_route.name == "forklift.legacy.file_upload"
    request.path_info = ECHO_PATH
    request.query_string = "jwt_audience=api"
    request.headers["X-JWT-Audience"] = API_AUDIENCE

    assert request.identity is None


def test_committed_revocation_denies_authorization_with_cached_identity(
    app_config, make_request, claims, sign
):
    publisher = GitHubPublisherFactory()
    project = ProjectFactory(oidc_publishers=[publisher])

    # The request transaction stays open while a second transaction revokes the JWT.
    with Session(app_config.registry["sqlalchemy.engine"]) as writer:
        registry = DatabaseJWTRegistry(writer)
        token_id = registry.register(datetime.fromtimestamp(claims["exp"], UTC))
        writer.commit()

        try:
            token = sign(
                {
                    **claims,
                    "jti": str(token_id),
                    "aud": UPLOAD_AUDIENCE,
                    "sub": str(publisher.id),
                    "subject_kind": "publisher",
                    "authorization_details": [
                        {"type": "warehouse", "actions": ["projects:upload"]}
                    ],
                }
            )
            request = make_request(UPLOAD_PATH, token)
            identity = request.identity
            assert identity == PublisherTokenContext(publisher, claims=None)
            assert request.has_permission(Permissions.ProjectsUpload, project)

            registry.revoke(token_id)
            writer.commit()

            assert request.identity is identity
            result = request.has_permission(Permissions.ProjectsUpload, project)
            assert not result
            assert result.reason == "invalid_jwt"
        finally:
            registry.revoke(token_id)
            writer.commit()
