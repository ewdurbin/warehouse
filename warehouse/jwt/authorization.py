# SPDX-License-Identifier: Apache-2.0

from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationType,
    ResourceKind,
    SubjectKind,
    VerifiedJWT,
)
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.packaging.models import Project


def permits(verified: VerifiedJWT, identity, context, permission) -> bool:
    """Check that the token matches the identity, permission, and resource.

    The caller verifies the token, checks the registry and allowed method, and
    enforces the resource ACL.
    """
    if verified.subject.kind == SubjectKind.USER:
        if (
            not isinstance(identity, UserContext)
            or identity.macaroon is not None
            or str(identity.user.id) != str(verified.subject.id)
        ):
            return False
    elif verified.subject.kind == SubjectKind.PUBLISHER:
        if not isinstance(identity, PublisherTokenContext) or str(
            identity.publisher.id
        ) != str(verified.subject.id):
            return False
    else:
        # Reject unknown subject kinds if a caller bypasses profile validation.
        return False  # type: ignore[unreachable]

    if not isinstance(permission, Permissions):
        return False
    # Uploads and observations require a project even when the token names none.
    if permission in (Permissions.ProjectsUpload, Permissions.APIObservationsAdd):
        if not isinstance(context, Project):
            return False
    elif permission != Permissions.APIEcho:
        return False

    for detail in verified.authorization_details:
        if (
            detail.type != AuthorizationType.WAREHOUSE
            or permission not in detail.actions
        ):
            continue
        if detail.resource is None:
            return True
        if (
            permission in (Permissions.ProjectsUpload, Permissions.APIObservationsAdd)
            and detail.resource.kind == ResourceKind.PROJECT
            and context.id == detail.resource.id
        ):
            return True
    return False
