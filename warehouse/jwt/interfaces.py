# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
from uuid import UUID

from zope.interface import Interface


class IJWTRegistry(Interface):
    """Track issued JWTs independently of their claims or authenticated identity.

    Mutations participate in the caller's transaction. Commit registration before
    returning a signed token, and commit revocation before acknowledging a burn.
    Database failures must propagate, never become successful validity checks.
    """

    def register(expires_at: datetime) -> UUID:
        """Register a fresh JTI with a future, timezone-aware expiration.

        Lifetime limits belong to the issuing/verifying JWT profile. IDs are
        generated here, not supplied by callers, and must never be reused.
        """

    def is_active(token_id: UUID) -> bool:
        """Check freshly whether the ID exists and has not expired.

        This is not JWT verification: callers must first validate the signed
        token, then separately enforce its restrictions and live resource ACLs.
        """

    def revoke(token_id: UUID) -> None:
        """Delete the ID; missing IDs are harmless. Callers authorize revocation."""

    def delete_expired() -> int:
        """Delete expired entries and return their count; never extend validity."""
