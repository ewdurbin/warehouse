# SPDX-License-Identifier: Apache-2.0

from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationType,
    ResourceKind,
    ResourceRef,
    SubjectKind,
    SubjectRef,
    VerifiedJWT,
)
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.packaging.models import Project


def permits(
    verified: VerifiedJWT,
    identity: UserContext | PublisherTokenContext,
    context: object,
    permission: Permissions,
) -> bool:
    """Check that the token matches the identity, permission, and resource.

    The caller verifies the token, checks the registry and allowed method, and
    enforces the resource ACL.
    """
    if isinstance(identity, UserContext) and identity.macaroon is None:
        subject = SubjectRef(SubjectKind.USER, identity.user.id)
    elif isinstance(identity, PublisherTokenContext):
        subject = SubjectRef(SubjectKind.PUBLISHER, identity.publisher.id)
    else:
        return False

    if verified.subject != subject or not isinstance(permission, Permissions):
        return False

    resource = None
    if permission in (Permissions.ProjectsUpload, Permissions.APIObservationsAdd):
        if not isinstance(context, Project):
            return False
        resource = ResourceRef(ResourceKind.PROJECT, context.id)
    elif permission != Permissions.APIEcho:
        return False

    return any(
        detail.type == AuthorizationType.WAREHOUSE
        and permission in detail.actions
        and (detail.resource is None or detail.resource == resource)
        for detail in verified.authorization_details
    )
