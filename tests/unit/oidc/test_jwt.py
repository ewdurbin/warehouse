# SPDX-License-Identifier: Apache-2.0

import json

from datetime import UTC, datetime

import pytest

from freezegun import freeze_time
from sqlalchemy import func, select

from tests.common.constants import DUMMY_GITHUB_OIDC_JWT
from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import PendingGitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from warehouse.authnz import Permissions
from warehouse.events.tags import EventTag
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.models import IssuedJWT
from warehouse.macaroons.models import Macaroon
from warehouse.oidc import views
from warehouse.oidc.models import GitHubPublisher
from warehouse.packaging.models import Project
from warehouse.rate_limiting import DummyRateLimiter
from warehouse.rate_limiting.interfaces import IRateLimiter


def request_jwt(db_request, **extra):
    db_request.body = json.dumps(
        {"token": DUMMY_GITHUB_OIDC_JWT, "token_format": "jwt", **extra}
    )
    return views.mint_token_from_oidc(db_request)


@pytest.mark.parametrize("value", [None, "", "JWT", "other", 1, True, [], {}])
def test_unknown_format_has_no_side_effects(db_request, value, mocker):
    mint = mocker.spy(views, "mint_token")
    response = request_jwt(db_request, token_format=value)
    assert db_request.response.status_code == 422
    assert response["errors"][0]["code"] == "invalid-payload"
    mint.assert_not_called()


def test_disabled_issuance_has_no_side_effects(db_request, github_oidc_service, mocker):
    verify = mocker.spy(github_oidc_service, "verify_jwt_signature")
    find = mocker.spy(github_oidc_service, "find_publisher")
    consume = mocker.spy(github_oidc_service, "store_jwt_identifier")
    response = request_jwt(db_request)
    assert db_request.response.status_code == 422
    assert response["errors"] == [
        {"code": "not-enabled", "description": "JWT token issuance is not enabled"}
    ]
    verify.assert_not_called()
    find.assert_not_called()
    consume.assert_not_called()


@pytest.mark.parametrize("token_format", [None, "macaroon"])
def test_macaroon_remains_default(db_request, jwt_publisher, token_format, mocker):
    ProjectFactory(oidc_publishers=[jwt_publisher])
    payload = {"token": DUMMY_GITHUB_OIDC_JWT}
    if token_format is not None:
        payload["token_format"] = token_format
    db_request.body = json.dumps(payload)
    response = views.mint_token_from_oidc(db_request)
    assert response["token"].startswith("pypi-")
    assert response["expires"] > int(datetime.now(UTC).timestamp()) + 300
    assert db_request.db.scalar(select(func.count()).select_from(IssuedJWT)) == 0


def test_exchange_issues_publisher_upload_jwt(
    db_request,
    jwt_publisher,
    jwt_issuer,
    jwt_upload_verifier,
    github_oidc_service,
    mocker,
):
    projects = [ProjectFactory(oidc_publishers=[jwt_publisher]) for _ in range(3)]
    verify_upstream = mocker.spy(github_oidc_service, "verify_jwt_signature")
    with freeze_time("2026-10-22 12:00:00+00:00", ignore=["_pytest"]):
        response = request_jwt(
            db_request,
            sub="client-selected",
            aud="wrong-audience",
            lifetime=99999,
            authorization_details=[{"actions": ["*"]}],
        )
        verified = jwt_upload_verifier.verify(response["token"])
        assert verified.subject == SubjectRef(SubjectKind.PUBLISHER, jwt_publisher.id)
        assert verified.authorization_details == (
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,)
            ),
        )
        assert response["expires"] == int(verified.expires_at.timestamp())
        assert (verified.expires_at - verified.issued_at).total_seconds() == 300
        assert response["success"] is True
        entry = jwt_issuer.registry.get_active(verified.jti)
        assert entry.expires_at == verified.expires_at
        assert entry.additional == {
            "oidc": jwt_publisher.stored_claims(verify_upstream.spy_return)
        }
        assert db_request.db.scalar(select(func.count()).select_from(Macaroon)) == 0
        for project in projects:
            event = project.events.where(
                Project.Event.tag == EventTag.Project.ShortLivedAPITokenAdded
            ).one()
            assert event.additional["expires"] == response["expires"]


def test_pending_publisher_can_opt_in(
    db_request, jwt_issuer, jwt_upload_verifier, pyramid_services, mocker
):
    user = UserFactory()
    pending = PendingGitHubPublisherFactory(
        project_name="jwt-pending-project",
        added_by=user,
        repository_name="bar",
        repository_owner="foo",
        repository_owner_id="123",
        workflow_filename="example.yml",
        environment="fake",
    )
    for name in ("user_oidc.publisher.register", "ip_oidc.publisher.register"):
        pyramid_services.register_service(
            DummyRateLimiter(), IRateLimiter, None, name=name
        )
    send_email = mocker.patch.object(
        views, "send_pending_trusted_publisher_reified_email"
    )
    response = request_jwt(db_request)
    project = db_request.db.scalar(
        select(Project).where(Project.name == pending.project_name)
    )
    publisher = db_request.db.scalar(select(GitHubPublisher))
    assert project.oidc_publishers == [publisher]
    assert jwt_upload_verifier.verify(response["token"]).subject == SubjectRef(
        SubjectKind.PUBLISHER, publisher.id
    )
    assert db_request.db.scalar(select(func.count()).select_from(Macaroon)) == 0
    send_email.assert_called_once()


@pytest.mark.parametrize("failure", ["signature", "publisher", "replay"])
def test_failed_upstream_validation_cannot_issue(
    db_request, jwt_publisher, jwt_issuer, github_oidc_service, failure, mocker
):
    ProjectFactory(oidc_publishers=[jwt_publisher])
    issue = mocker.spy(jwt_issuer, "issue")
    if failure == "signature":
        mocker.patch.object(
            github_oidc_service, "verify_jwt_signature", return_value=None
        )
    elif failure == "publisher":
        jwt_publisher.repository_owner = "other-owner"
    else:
        claims = github_oidc_service.verify_jwt_signature(
            DUMMY_GITHUB_OIDC_JWT, "https://token.actions.githubusercontent.com"
        )
        claims.update(jti="already-used", exp=9999999999)
        mocker.patch.object(
            github_oidc_service, "verify_jwt_signature", return_value=claims
        )
        mocker.patch.object(
            github_oidc_service, "store_jwt_identifier", return_value=False
        )
    response = request_jwt(db_request)
    assert db_request.response.status_code == 422
    assert response["errors"]
    issue.assert_not_called()


def test_replay_claim_precedes_issuance(
    db_request, jwt_publisher, jwt_issuer, github_oidc_service, mocker
):
    ProjectFactory(oidc_publishers=[jwt_publisher])
    claims = github_oidc_service.verify_jwt_signature(
        DUMMY_GITHUB_OIDC_JWT, "https://token.actions.githubusercontent.com"
    )
    claims.update(jti="single-use", exp=9999999999)
    mocker.patch.object(
        github_oidc_service, "verify_jwt_signature", return_value=claims
    )
    order = []

    def consume(*args):
        order.append("consume")
        return True

    mocker.patch.object(
        github_oidc_service, "store_jwt_identifier", side_effect=consume
    )
    original = jwt_issuer.issue

    def issue(**kwargs):
        order.append("issue")
        return original(**kwargs)

    mocker.patch.object(jwt_issuer, "issue", side_effect=issue)
    assert request_jwt(db_request)["success"]
    assert order == ["consume", "issue"]


def test_signing_failure_propagates_and_rolls_back(
    db_request, jwt_publisher, jwt_issuer, mocker
):
    ProjectFactory(oidc_publishers=[jwt_publisher])
    mocker.patch(
        "warehouse.jwt.issuer.jwt.encode", side_effect=RuntimeError("signing failed")
    )
    with (
        pytest.raises(RuntimeError, match="signing failed"),
        db_request.db.begin_nested(),
    ):
        request_jwt(db_request)
    assert db_request.db.scalar(select(func.count()).select_from(IssuedJWT)) == 0
