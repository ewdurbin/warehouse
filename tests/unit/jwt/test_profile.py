# SPDX-License-Identifier: Apache-2.0


import pytest

from warehouse.jwt.profile import (
    MAX_LIFETIME_SECONDS,
    MEDIA_TYPE,
    is_uuid,
    valid_authorization_details,
)

PROJECT_ID = "95ea64e2-764c-4320-a4e5-991df49f261f"


def test_profile_constants():
    assert MEDIA_TYPE == "pypi-access+jwt"
    assert MAX_LIFETIME_SECONDS == 300


@pytest.mark.parametrize(
    "value",
    [None, True, 1, [], {}, "", "not-a-uuid", "DDf9597e-dda1-45a2-b026-3a090ad7c4b2"],
)
def test_invalid_uuid(value):
    assert not is_uuid(value)


def test_canonical_uuid():
    assert is_uuid("ddf9597e-dda1-45a2-b026-3a090ad7c4b2")


@pytest.mark.parametrize(
    "action", ["projects:upload", "api:echo", "api:observations:add"]
)
def test_permission_wide_details(action):
    assert valid_authorization_details([{"type": "warehouse", "actions": [action]}])


@pytest.mark.parametrize(
    "actions",
    [
        ["projects:upload"],
        ["api:observations:add"],
        ["projects:upload", "api:observations:add"],
    ],
)
def test_project_narrowing(actions):
    assert valid_authorization_details(
        [
            {
                "type": "warehouse",
                "actions": actions,
                "identifier": f"project:{PROJECT_ID}",
            }
        ]
    )


@pytest.mark.parametrize(
    "details",
    [
        None,
        {},
        [],
        "upload",
        [None],
        [{}],
        [{"type": "other", "actions": ["projects:upload"]}],
    ],
)
def test_invalid_details(details):
    assert not valid_authorization_details(details)


@pytest.mark.parametrize(
    "actions",
    [
        None,
        [],
        "projects:upload",
        [True],
        [None],
        ["unknown"],
        ["projects:upload", "unknown"],
    ],
)
def test_invalid_actions(actions):
    assert not valid_authorization_details([{"type": "warehouse", "actions": actions}])


@pytest.mark.parametrize(
    "identifier",
    [
        None,
        False,
        1,
        [],
        {},
        "",
        "*",
        PROJECT_ID,
        {"kind": "project", "id": PROJECT_ID},
        "project:",
        "project:bad",
        "project:*",
        f":{PROJECT_ID}",
        f"PROJECT:{PROJECT_ID}",
        f"project:{PROJECT_ID.upper()}",
        f"project:{{{PROJECT_ID}}}",
        f"project:{PROJECT_ID.replace('-', '')}",
        f"project:{PROJECT_ID}:extra",
        f"project:{PROJECT_ID}\n",
        f" project:{PROJECT_ID}",
        f"organization:{PROJECT_ID}",
        f"user:{PROJECT_ID}",
        f"publisher:{PROJECT_ID}",
        f"publisher-projects:{PROJECT_ID}",
    ],
)
def test_invalid_identifier(identifier):
    assert not valid_authorization_details(
        [
            {
                "type": "warehouse",
                "actions": ["projects:upload"],
                "identifier": identifier,
            }
        ]
    )


def test_identifier_must_support_every_action():
    assert not valid_authorization_details(
        [
            {
                "type": "warehouse",
                "actions": ["projects:upload", "api:echo"],
                "identifier": f"project:{PROJECT_ID}",
            }
        ]
    )


def test_unknown_fields_fail_closed():
    assert not valid_authorization_details(
        [{"type": "warehouse", "actions": ["projects:upload"], "unknown": True}]
    )
