# SPDX-License-Identifier: Apache-2.0

from uuid import UUID

import pytest

from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
)
from warehouse.jwt.profile import parse_authorization_details, parse_uuid

PROJECT_ID = "95ea64e2-764c-4320-a4e5-991df49f261f"


def test_canonical_uuid():
    assert parse_uuid(PROJECT_ID) == UUID(PROJECT_ID)


@pytest.mark.parametrize("value", [None, "not-a-uuid", PROJECT_ID.upper()])
def test_invalid_uuid(value):
    assert parse_uuid(value) is None


@pytest.mark.parametrize(
    "permission",
    [Permissions.ProjectsUpload, Permissions.APIEcho, Permissions.APIObservationsAdd],
)
def test_omitted_identifier_leaves_resource_unrestricted(permission):
    assert parse_authorization_details(
        [{"type": "warehouse", "actions": [permission.value]}]
    ) == (AuthorizationDetail(AuthorizationType.WAREHOUSE, (permission,)),)


def test_project_identifier_restricts_every_action():
    assert parse_authorization_details(
        [
            {
                "type": "warehouse",
                "actions": ["projects:upload", "api:observations:add"],
                "identifier": f"project:{PROJECT_ID}",
            }
        ]
    ) == (
        AuthorizationDetail(
            AuthorizationType.WAREHOUSE,
            (Permissions.ProjectsUpload, Permissions.APIObservationsAdd),
            ResourceRef(ResourceKind.PROJECT, UUID(PROJECT_ID)),
        ),
    )


@pytest.mark.parametrize(
    "details",
    [
        {},
        [],
        [None],
        [{"type": "warehouse"}],
        [{"type": "other", "actions": ["projects:upload"]}],
    ],
)
def test_invalid_details(details):
    assert parse_authorization_details(details) is None


@pytest.mark.parametrize(
    "actions", [[], "projects:upload", [True], ["projects:upload", "unknown"]]
)
def test_invalid_actions(actions):
    assert (
        parse_authorization_details([{"type": "warehouse", "actions": actions}]) is None
    )


@pytest.mark.parametrize(
    "identifier",
    [
        None,
        {"kind": "project", "id": PROJECT_ID},
        PROJECT_ID,
        "project:bad",
        f"project:{PROJECT_ID.upper()}",
        f"organization:{PROJECT_ID}",
    ],
)
def test_invalid_identifier(identifier):
    assert (
        parse_authorization_details(
            [
                {
                    "type": "warehouse",
                    "actions": ["projects:upload"],
                    "identifier": identifier,
                }
            ]
        )
        is None
    )


def test_identifier_must_support_every_action():
    assert (
        parse_authorization_details(
            [
                {
                    "type": "warehouse",
                    "actions": ["projects:upload", "api:echo"],
                    "identifier": f"project:{PROJECT_ID}",
                }
            ]
        )
        is None
    )


def test_unknown_field_rejects_entire_claim():
    assert (
        parse_authorization_details(
            [
                {"type": "warehouse", "actions": ["projects:upload"]},
                {
                    "type": "warehouse",
                    "actions": ["projects:upload"],
                    "unknown": True,
                },
            ]
        )
        is None
    )
