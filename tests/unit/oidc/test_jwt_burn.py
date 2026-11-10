# SPDX-License-Identifier: Apache-2.0

import json

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from sqlalchemy import Delete, delete, event
from sqlalchemy.orm import Session
from webtest import TestApp

from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from tests.conftest import get_app_config
from warehouse.authnz import Permissions
from warehouse.events.tags import EventTag
from warehouse.ip_addresses.models import IpAddress
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    SubjectKind,
    SubjectRef,
)
from warehouse.jwt.interfaces import IJWTSigner, IJWTVerifier
from warehouse.jwt.issuer import WarehouseJWTIssuer
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    WarehouseJWTVerifierFactory,
    jwt_issuer_factory,
)
from warehouse.oidc import views
from warehouse.oidc.models import GitHubPublisher
from warehouse.packaging.models import Project


@pytest.fixture
def issuer(db_request, pyramid_services, warehouse_jwt_settings, warehouse_jwt_signer):
    pyramid_services.register_service(warehouse_jwt_signer, IJWTSigner, None)
    return jwt_issuer_factory(warehouse_jwt_settings)(None, db_request)


@pytest.fixture
def publisher(db_session):
    return GitHubPublisherFactory()


def issue_upload_jwt(
    issuer, publisher, *, kind=SubjectKind.PUBLISHER, audience="upload"
):
    return issuer.issue(
        subject=SubjectRef(kind, publisher.id),
        audience=audience,
        authorization_details=(
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,)
            ),
        ),
    )


class TestBurnJWT:
    @pytest.fixture(autouse=True)
    def setup_verifier(self, pyramid_services, warehouse_jwt_settings):
        verifier = WarehouseJWTVerifierFactory(warehouse_jwt_settings).for_audience(
            "upload"
        )
        pyramid_services.register_service(verifier, IJWTVerifier, None, name="upload")

    @pytest.fixture
    def issued(self, publisher, issuer):
        return issue_upload_jwt(issuer, publisher)

    def burn(self, request, issued):
        request.body = json.dumps({"token": issued.token})
        response = views.burn_oidc_issued_token(request)
        assert request.response.status_code == 202
        assert response == {"message": "Accepted", "errors": []}

    def test_burns_only_presented_token_and_is_idempotent(
        self, db_request, issued, issuer, publisher, jwt_registry, metrics
    ):
        project = ProjectFactory(oidc_publishers=[publisher])
        other = issue_upload_jwt(issuer, publisher)

        self.burn(db_request, issued)
        self.burn(db_request, issued)

        assert not jwt_registry.is_active(issued.jti)
        assert jwt_registry.is_active(other.jti)
        assert (
            project.events.where(
                Project.Event.tag == EventTag.Project.ShortLivedAPITokenRevoked
            ).count()
            == 1
        )
        metrics.increment.assert_called_once_with(
            "warehouse.oidc.burn_oidc_issued_token",
            tags=["status:success", "token_format:jwt"],
        )

    @pytest.mark.parametrize(
        ("kind", "audience"),
        [
            pytest.param(SubjectKind.PUBLISHER, "api", id="api-audience"),
            pytest.param(SubjectKind.USER, "upload", id="user-subject"),
        ],
    )
    def test_rejects_tokens_outside_the_burn_policy(
        self, db_request, issuer, publisher, jwt_registry, kind, audience
    ):
        issued = issue_upload_jwt(issuer, publisher, kind=kind, audience=audience)
        self.burn(db_request, issued)
        assert jwt_registry.is_active(issued.jti)

    def test_deleted_publisher_can_still_revoke(
        self, db_request, issued, jwt_registry, publisher
    ):
        db_request.db.delete(publisher)
        db_request.db.flush()

        self.burn(db_request, issued)

        assert not jwt_registry.is_active(issued.jti)

    def test_caller_owns_transaction(self, db_request, issued, jwt_registry):
        with db_request.db.begin_nested() as transaction:
            self.burn(db_request, issued)
            assert not jwt_registry.is_active(issued.jti)
            transaction.rollback()

        assert jwt_registry.is_active(issued.jti)


def test_concurrent_burns_record_one_event(
    database, warehouse_jwt_settings, warehouse_jwt_signer
):
    signing_config = jwt_issuer_factory(warehouse_jwt_settings)
    del warehouse_jwt_settings["warehouse.jwt.kms_key_id"]
    del warehouse_jwt_settings["warehouse.jwt.signing_key_id"]
    config = get_app_config(database, warehouse_jwt_settings | {"enforce_https": False})
    app = config.make_wsgi_app()
    engine = config.registry["sqlalchemy.engine"]
    publisher = GitHubPublisherFactory.build()
    project = ProjectFactory.build(oidc_publishers=[publisher])
    addresses = ("192.0.2.113", "192.0.2.114")

    with Session(engine) as session:
        session.add(project)
        issuer = WarehouseJWTIssuer(
            registry=DatabaseJWTRegistry(session),
            signer=warehouse_jwt_signer,
            config=signing_config,
        )
        issued = issue_upload_jwt(issuer, publisher)
        session.commit()
        publisher_id = publisher.id
        project_id = project.id

    both_deleting = Barrier(2)

    def wait_for_burns(conn, cursor, statement, parameters, context, executemany):
        if (
            context.compiled is not None
            and isinstance(context.compiled.statement, Delete)
            and context.compiled.statement.table.name == IssuedJWT.__tablename__
        ):
            both_deleting.wait(timeout=10)

    def burn(address):
        client = TestApp(app, extra_environ={"REMOTE_ADDR": address})
        return client.post_json(
            "/_/oidc/burn-token", {"token": issued.token}, status=202
        )

    try:
        event.listen(engine, "before_cursor_execute", wait_for_burns)
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(burn, addresses))
        finally:
            event.remove(engine, "before_cursor_execute", wait_for_burns)

        assert [response.json for response in responses] == [
            {"message": "Accepted", "errors": []},
            {"message": "Accepted", "errors": []},
        ]
        with Session(engine) as session:
            assert session.get(IssuedJWT, issued.jti) is None
            project = session.get(Project, project_id)
            assert (
                project.events.where(
                    Project.Event.tag == EventTag.Project.ShortLivedAPITokenRevoked
                ).count()
                == 1
            )
    finally:
        with Session(engine) as session:
            session.execute(delete(IssuedJWT).where(IssuedJWT.id == issued.jti))
            session.delete(session.get(Project, project_id))
            session.delete(session.get(GitHubPublisher, publisher_id))
            session.flush()
            session.execute(
                delete(IpAddress).where(IpAddress.ip_address.in_(addresses))
            )
            session.commit()
        engine.dispose()
