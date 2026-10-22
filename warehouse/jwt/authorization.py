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
    """Check subject binding and details, not validity, registry liveness, or ACLs.

    The caller must supply a freshly verified result for the original credential.
    Resource adapters live here, not in the cryptographic verifier. Unsupported
    identities, permissions, and resource types never imply unrestricted access.
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
    # Permission-wide is not context-free: uploads and observations still act on
    # projects. ACLs decide the subject's current privileges on each project.
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
