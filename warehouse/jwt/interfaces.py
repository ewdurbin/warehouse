# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
from uuid import UUID

from zope.interface import Interface

from warehouse.jwt.claims import VerifiedJWT


class IJWTVerifier(Interface):
    def verify(token: str) -> VerifiedJWT | None:
        """Validate a JWT and return normalized, immutable verified claims.

        Implementations must validate the signature, configured algorithm and
        issuer/key binding, audience, token purpose, required claims, and time
        bounds. Subject kinds and authorization details types, actions, and
        identifiers must be explicitly supported by the token profile. Unknown
        claims or restrictions must fail closed, never be ignored. An absent
        identifier means no token-level resource narrowing in the Warehouse
        profile; an invalid identifier must not be treated as absent.
        An unverified subject must never be resolved as an identity. Invalid
        credentials return None; infrastructure and configuration failures raise.

        Bind the service to its intended recipient using trusted server-side
        route configuration. Token claims must not select the expected issuer
        or audience.

        This performs no database lookups or resource authorization. Callers must
        check registry liveness, resolve the typed subject and its current status,
        and enforce authorization details, the method allowlist, and live ACLs.
        Reverify at authorization time, even when request identity is cached;
        the resolved identity must still match the verified subject kind and ID.
        """


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
