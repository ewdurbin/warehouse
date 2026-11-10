# SPDX-License-Identifier: Apache-2.0

import json

from datetime import UTC, datetime

import jwt
import pytest

from freezegun import freeze_time
from sqlalchemy import func, select

from tests.common.constants import DUMMY_GITHUB_OIDC_JWT
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
from warehouse.packaging.models import Project


def request_jwt(db_request, **extra):
    db_request.body = json.dumps(
        {"token": DUMMY_GITHUB_OIDC_JWT, "token_format": "jwt", **extra}
    )
    return views.mint_token_from_oidc(db_request)


@pytest.mark.parametrize("value", [None, "other", 1])
def test_unknown_format_is_rejected(db_request, value):
    response = request_jwt(db_request, token_format=value)
    assert db_request.response.status_code == 422
    assert response["errors"][0]["code"] == "invalid-payload"


def test_disabled_issuance_has_no_side_effects(db_request, github_oidc_service, mocker):
    claim = mocker.spy(github_oidc_service, "store_jwt_identifier")
    response = request_jwt(db_request)
    assert db_request.response.status_code == 422
    assert response["errors"] == [
        {"code": "not-enabled", "description": "JWT issuance is disabled"}
    ]
    claim.assert_not_called()


def test_explicit_macaroon_format(db_request, jwt_publisher):
    ProjectFactory(oidc_publishers=[jwt_publisher])
    payload = {"token": DUMMY_GITHUB_OIDC_JWT, "token_format": "macaroon"}
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
):
    projects = [ProjectFactory(oidc_publishers=[jwt_publisher]) for _ in range(3)]
    upstream_claims = jwt.decode(
        DUMMY_GITHUB_OIDC_JWT, options={"verify_signature": False}
    )
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
            "oidc": {"ref": upstream_claims["ref"], "sha": upstream_claims["sha"]}
        }
        assert db_request.db.scalar(select(func.count()).select_from(Macaroon)) == 0
        for project in projects:
            event = project.events.where(
                Project.Event.tag == EventTag.Project.ShortLivedAPITokenAdded
            ).one()
            assert event.additional["expires"] == response["expires"]


def test_signing_failure_propagates_and_rolls_back(
    db_request, jwt_publisher, jwt_issuer, mocker
):
    ProjectFactory(oidc_publishers=[jwt_publisher])
    mocker.patch.object(
        type(jwt_issuer.signer), "sign", side_effect=RuntimeError("signing failed")
    )
    with (
        pytest.raises(RuntimeError, match="signing failed"),
        db_request.db.begin_nested(),
    ):
        request_jwt(db_request)
    assert db_request.db.scalar(select(func.count()).select_from(IssuedJWT)) == 0
