# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime
from uuid import UUID

import pytest

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
