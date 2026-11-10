# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from zope.interface import Attribute, Interface

from warehouse.jwt.claims import AuthorizationDetail, SignedJWT, SubjectRef, VerifiedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS

if TYPE_CHECKING:
    from warehouse.jwt.models import IssuedJWT


class IJWTVerifier(Interface):
    def verify(token: str) -> VerifiedJWT | None:
        """Verify the configured Warehouse JWT profile and return immutable claims.

        Return None for invalid tokens and propagate configuration or service
        errors. The caller enforces live authorization.
        """


class IJWTSigner(Interface):
    def sign(claims: dict[str, object]) -> str:
        """Sign server-selected claims as a compact Warehouse access JWT.

        The signer sets the algorithm, token type, and key ID. The caller
        validates the claims and handles registration and authorization.
        If signing fails with the configured key, raise the error.
        """


class IJWTIssuer(Interface):
    enabled = Attribute("Whether new JWTs can be issued with this configuration")

    def issue(
        *,
        subject: SubjectRef,
        audience: str,
        authorization_details: tuple[AuthorizationDetail, ...],
        lifetime: int = MAX_LIFETIME_SECONDS,
        additional: dict | None = None,
    ) -> SignedJWT:
        """Register and sign a credential using trusted, authorized inputs.

        The caller authorizes issuance and selects the subject, configured
        audience label, and authorization details. The lifetime is an integer
        from 1 to 300 seconds. The registry holds any additional metadata.

        The caller owns the transaction. Commit before handing out the token
        and roll back on failure. Raise if issuance is disabled, inputs are
        invalid, a service fails, or the token expires during signing.
        """


class IJWTRegistry(Interface):
    """Track issued JWT IDs, expiration times, and metadata.

    The caller owns the transaction. Commit registration before returning a
    token and commit revocation before acknowledging a burn. Propagate database
    errors.
    """

    def register(expires_at: datetime, *, additional: dict | None = None) -> UUID:
        """Register a fresh JTI with a future, timezone-aware expiration.

        The registry generates a new ID for each token. The JWT profile defines
        the lifetime limit. Trusted issuing code can supply JSON metadata for
        uses such as recording provenance. Access depends on the signed claims
        and the resource ACL.
        """

    def get_active(token_id: UUID) -> IssuedJWT | None:
        """Query for an unexpired entry and its metadata.

        Return None if the entry is absent or expired. Verify the token before
        using its ID here.
        """

    def is_active(token_id: UUID) -> bool:
        """Query for an unexpired entry by ID.

        Verify the token first. For access to a resource, also check the token's
        authorization details and the resource ACL.
        """

    def revoke(token_id: UUID) -> bool:
        """Delete an unexpired entry and return whether it was deleted.

        The caller authorizes revocation.
        """
