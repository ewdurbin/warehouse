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
    """Check authorization details against the resolved subject and context.

    The caller must verify the original credential, check registry liveness, and
    enforce ACLs. Unsupported identities, permissions, and resources are denied.
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
        # Reject malformed runtime values even though the typed enum is exhaustive.
        return False  # type: ignore[unreachable]

    if not isinstance(permission, Permissions):
        return False
    # Uploads and observations require a project context; ACLs check the
    # subject's current privileges on that project.
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
