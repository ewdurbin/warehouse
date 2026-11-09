# SPDX-License-Identifier: Apache-2.0

from uuid import UUID

from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
)

MEDIA_TYPE = "pypi-access+jwt"
MAX_LIFETIME_SECONDS = 300
MAX_TOKEN_LENGTH = 8 * 1024

_ACTION_RESOURCES = {
    Permissions.ProjectsUpload: (ResourceKind.PROJECT,),
    Permissions.APIEcho: (),
    Permissions.APIObservationsAdd: (ResourceKind.PROJECT,),
}


def parse_uuid(value: object) -> UUID | None:
    """Parse the canonical string representation of a Warehouse ID."""
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value else None


def parse_authorization_details(
    details: object,
) -> tuple[AuthorizationDetail, ...] | None:
    """Parse the claim, rejecting it if any authorization detail is invalid."""
    if not isinstance(details, list) or not details:
        return None
    parsed = []
    for detail in details:
        if not isinstance(detail, dict) or set(detail) not in (
            {"type", "actions"},
            {"type", "actions", "identifier"},
        ):
            return None
        if detail["type"] != AuthorizationType.WAREHOUSE:
            return None
        actions = detail["actions"]
        if (
            not isinstance(actions, list)
            or not actions
            or any(
                not isinstance(action, str) or action not in _ACTION_RESOURCES
                for action in actions
            )
        ):
            return None
        resource = None
        if "identifier" in detail:
            # Only an omitted identifier leaves the resource unrestricted.
            identifier = detail["identifier"]
            if not isinstance(identifier, str):
                return None
            kind, _, raw_id = identifier.partition(":")
            resource_id = parse_uuid(raw_id)
            if resource_id is None or any(
                kind not in _ACTION_RESOURCES[action] for action in actions
            ):
                return None
            resource = ResourceRef(ResourceKind(kind), resource_id)
        parsed.append(
            AuthorizationDetail(
                type=AuthorizationType.WAREHOUSE,
                actions=tuple(Permissions(action) for action in actions),
                resource=resource,
            )
        )
    return tuple(parsed)
