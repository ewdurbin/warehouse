# SPDX-License-Identifier: Apache-2.0

from uuid import UUID

from warehouse.authnz import Permissions
from warehouse.jwt.claims import AuthorizationType, ResourceKind

MEDIA_TYPE = "pypi-access+jwt"
MAX_LIFETIME_SECONDS = 300

_ACTION_RESOURCES = {
    Permissions.ProjectsUpload: (ResourceKind.PROJECT,),
    Permissions.APIEcho: (),
    Permissions.APIObservationsAdd: (ResourceKind.PROJECT,),
}


def is_uuid(value) -> bool:
    """Require the canonical string representation of a Warehouse ID."""
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def valid_authorization_details(details) -> bool:
    """Validate the wire profile shared by issuance and verification."""
    if not isinstance(details, list) or not details:
        return False
    for detail in details:
        if not isinstance(detail, dict) or set(detail) not in (
            {"type", "actions"},
            {"type", "actions", "identifier"},
        ):
            return False
        if detail["type"] != AuthorizationType.WAREHOUSE:
            return False
        actions = detail["actions"]
        if (
            not isinstance(actions, list)
            or not actions
            or any(
                not isinstance(action, str) or action not in _ACTION_RESOURCES
                for action in actions
            )
        ):
            return False
        if "identifier" in detail:
            # An absent identifier imposes no resource restriction; an invalid
            # one must be rejected.
            identifier = detail["identifier"]
            if not isinstance(identifier, str):
                return False
            kind, _, resource_id = identifier.partition(":")
            if not is_uuid(resource_id) or any(
                kind not in _ACTION_RESOURCES[action] for action in actions
            ):
                return False
    return True
