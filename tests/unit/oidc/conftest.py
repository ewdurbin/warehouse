# SPDX-License-Identifier: Apache-2.0

import pytest

from tests.common.db.oidc import GitHubPublisherFactory
from warehouse.jwt.interfaces import IJWTIssuer, IJWTSigner
from warehouse.jwt.services import jwt_issuer_factory, jwt_verifier_factory


@pytest.fixture
def jwt_issuer(
    db_request, pyramid_services, warehouse_jwt_settings, warehouse_jwt_signer
):
    pyramid_services.register_service(warehouse_jwt_signer, IJWTSigner, None)
    issuer = jwt_issuer_factory(warehouse_jwt_settings)(None, db_request)
    pyramid_services.register_service(issuer, IJWTIssuer, None)
    return issuer


@pytest.fixture
def jwt_upload_verifier(db_request, warehouse_jwt_settings):
    return jwt_verifier_factory(warehouse_jwt_settings).for_audience("upload")(
        None, db_request
    )


@pytest.fixture
def jwt_publisher(db_session):
    return GitHubPublisherFactory(
        repository_name="bar",
        repository_owner="foo",
        repository_owner_id="123",
        workflow_filename="example.yml",
        environment="fake",
    )
