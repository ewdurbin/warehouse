# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from warehouse.authnz import Permissions


class SubjectKind(StrEnum):
    USER = "user"
    PUBLISHER = "publisher"


class ResourceKind(StrEnum):
    PROJECT = "project"


class AuthorizationType(StrEnum):
    WAREHOUSE = "warehouse"


@dataclass(frozen=True)
class SubjectRef:
    kind: SubjectKind
    id: UUID


@dataclass(frozen=True)
class ResourceRef:
    kind: ResourceKind
    id: UUID


@dataclass(frozen=True)
class AuthorizationDetail:
    """A normalized RFC 9396 authorization details object.

    The resource restricts all actions in this object. If the token omits the
    identifier, resource is None and the actions apply to any eligible resource.
    Each object applies independently. The resource ACL must still allow access.
    """

    type: AuthorizationType
    actions: tuple[Permissions, ...]
    resource: ResourceRef | None = None


@dataclass(frozen=True)
class VerifiedJWT:
    """Immutable claims from a token that passed verification.

    The caller checks the registry, resolves the subject, and authorizes access.
    """

    jti: UUID
    subject: SubjectRef
    issuer: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    authorization_details: tuple[AuthorizationDetail, ...]


@dataclass(frozen=True)
class SignedJWT:
    """A signed token with its registry ID and expiration time."""

    token: str = field(repr=False)
    jti: UUID
    expires_at: datetime
