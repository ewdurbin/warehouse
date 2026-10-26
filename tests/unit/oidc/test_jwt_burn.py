# SPDX-License-Identifier: Apache-2.0

import json

from datetime import UTC, datetime
from uuid import uuid7

import jwt
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.exc import OperationalError

from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from warehouse.authnz import Permissions
from warehouse.events.tags import EventTag
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.interfaces import IJWTIssuer, IJWTSigner, IJWTVerifier
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.services import (
    DisabledJWTVerifier,
    jwt_issuer_factory,
    jwt_verifier_factory,
)
from warehouse.jwt.verifier import WarehouseJWTVerifier
from warehouse.oidc import views
from warehouse.packaging.models import Project


@pytest.fixture
def issuer(db_request, pyramid_services, warehouse_jwt_settings, warehouse_jwt_signer):
    pyramid_services.register_service(warehouse_jwt_signer, IJWTSigner, None)
    service = jwt_issuer_factory(warehouse_jwt_settings)(None, db_request)
    pyramid_services.register_service(service, IJWTIssuer, None)
    return service


@pytest.fixture
def verifier(warehouse_jwt_key, warehouse_jwt_settings):
    return WarehouseJWTVerifier(
        issuer=warehouse_jwt_settings["warehouse.jwt.issuer"],
        audience=warehouse_jwt_settings["warehouse.jwt.upload_audience"],
        keys={"current": warehouse_jwt_key.public_key()},
    )


@pytest.fixture
def publisher(db_session):
    return GitHubPublisherFactory(
        repository_name="bar",
        repository_owner="foo",
        repository_owner_id="123",
        workflow_filename="example.yml",
        environment="fake",
    )


def issue_upload_jwt(issuer, publisher):
    """Issue directly so burn tests do not depend on the exchange endpoint."""
    return issuer.issue(
        subject=SubjectRef(SubjectKind.PUBLISHER, publisher.id),
        audience="upload",
        authorization_details=(
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,)
            ),
        ),
    ).token


class TestBurnJWT:
    @pytest.fixture(autouse=True)
    def setup_verifier(self, db_request, pyramid_services, warehouse_jwt_settings):
        verifier = jwt_verifier_factory(warehouse_jwt_settings).for_audience("upload")(
            None, db_request
        )
        pyramid_services.register_service(verifier, IJWTVerifier, None, name="upload")

    @pytest.fixture
    def issued(self, db_request, publisher, issuer, verifier):
        ProjectFactory(oidc_publishers=[publisher])
        token = issue_upload_jwt(issuer, publisher)
        return token, verifier.verify(token)

    def burn(self, request, token):
        request.body = json.dumps({"token": token})
        response = views.burn_oidc_issued_token(request)
        assert request.response.status_code == 202
        assert response == {"message": "Accepted", "errors": []}

    def test_burns_only_presented_token_and_is_idempotent(
        self, db_request, issued, issuer, publisher, verifier
    ):
        token, verified = issued
        other = issue_upload_jwt(issuer, publisher)
        self.burn(db_request, token)
        self.burn(db_request, token)
        assert not issuer.registry.is_active(verified.jti)
        assert issuer.registry.is_active(verifier.verify(other).jti)
        for project in publisher.projects:
            events = project.events.where(
                Project.Event.tag == EventTag.Project.ShortLivedAPITokenRevoked
            ).all()
            assert len(events) == 1

    @pytest.mark.parametrize(
        "change",
        ["audience", "issuer", "subject", "expiry", "jti", "signature", "malformed"],
    )
    def test_rejects_invalid_tokens(
        self, db_request, issued, issuer, warehouse_jwt_key, change, mocker
    ):
        token, verified = issued
        claims = jwt.decode(token, options={"verify_signature": False})
        key = warehouse_jwt_key
        if change == "audience":
            claims["aud"] = "https://warehouse.example/api"
        elif change == "issuer":
            claims["iss"] = "https://wrong-issuer.example"
        elif change == "subject":
            claims["subject_kind"] = "user"
        elif change == "expiry":
            claims["iat"] -= 301
            claims["exp"] -= 301
        elif change == "jti":
            claims["jti"] = str(uuid7())
        elif change == "signature":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        candidate = jwt.encode(
            claims, key, algorithm="RS256", headers=jwt.get_unverified_header(token)
        )
        if change == "malformed":
            candidate = "invalid.jwt.token"
        revoke = mocker.spy(issuer.registry, "revoke")
        self.burn(db_request, candidate)
        revoke.assert_not_called()
        assert issuer.registry.is_active(verified.jti)

    def test_disabled_verifier_cannot_burn(
        self, db_request, issued, issuer, pyramid_services
    ):
        token, verified = issued
        pyramid_services.register_service(
            DisabledJWTVerifier(), IJWTVerifier, None, name="upload"
        )
        self.burn(db_request, token)
        assert issuer.registry.is_active(verified.jti)

    def test_expired_registry_entry_is_noop(self, db_request, issued, issuer, mocker):
        token, verified = issued
        db_request.db.get(IssuedJWT, verified.jti).expires_at = datetime.now(UTC)
        revoke = mocker.spy(issuer.registry, "revoke")
        self.burn(db_request, token)
        revoke.assert_not_called()

    def test_deleted_publisher_can_still_revoke(
        self, db_request, issued, issuer, publisher
    ):
        token, verified = issued
        db_request.db.delete(publisher)
        db_request.db.flush()
        self.burn(db_request, token)
        assert not issuer.registry.is_active(verified.jti)

    def test_caller_owns_transaction(self, db_request, issued, issuer):
        token, verified = issued
        with db_request.db.begin_nested() as transaction:
            self.burn(db_request, token)
            assert not issuer.registry.is_active(verified.jti)
            transaction.rollback()
        assert issuer.registry.is_active(verified.jti)

    @pytest.mark.parametrize("method", ["is_active", "revoke"])
    def test_database_failures_propagate(
        self, db_request, issued, issuer, mocker, method
    ):
        token, _ = issued
        mocker.patch.object(
            issuer.registry,
            method,
            side_effect=OperationalError(
                "statement", {}, Exception("database unavailable")
            ),
        )
        db_request.body = json.dumps({"token": token})
        with pytest.raises(OperationalError):
            views.burn_oidc_issued_token(db_request)
