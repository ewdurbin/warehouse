# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
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

    All actions in this object share its resource restriction. A missing wire
    identifier becomes resource=None, meaning no token-level resource narrowing.
    Objects are additive: a narrowed object does not restrict a broader one.
    Live ACL privileges remain mandatory in either case.
    """

    type: AuthorizationType
    actions: tuple[Permissions, ...]
    resource: ResourceRef | None = None


@dataclass(frozen=True)
class VerifiedJWT:
    """A verified claim snapshot, not a live identity or an authorization result.

    These values contain no request, ORM objects, or mutable claim dictionaries.
    Registry liveness, subject resolution, and authorization remain the caller's
    responsibility. A previously verified result must not bypass time checks.
    """

    jti: UUID
    subject: SubjectRef
    issuer: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    authorization_details: tuple[AuthorizationDetail, ...]
