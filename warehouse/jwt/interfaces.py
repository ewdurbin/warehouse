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

        Select the expected issuer and audience from trusted server-side
        configuration, not from token claims.

        This performs no database lookups or resource authorization. Callers must
        check registry liveness, resolve the typed subject and its current status,
        and enforce authorization details, the method allowlist, and live ACLs.
        Reverify and recheck registry liveness at authorization time, even when
        request identity is cached; the resolved identity must still match the
        verified subject kind and ID.
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
        audience name (not a client-supplied URI), and authorization details.
        Lifetime is an integer number of seconds, at most five minutes.
        Filtered per-issuance metadata stays in the registry, not the JWT.

        Mutations participate in the caller's transaction: commit before handing
        out the credential; roll back on failure. This service never commits.
        Invalid inputs, disabled issuance, and infrastructure errors raise.
        """


class IJWTRegistry(Interface):
    """Track issued JWTs independently of their claims or authenticated identity.

    Mutations participate in the caller's transaction. Commit registration before
    returning a signed token, and commit revocation before acknowledging a burn.
    Database failures must propagate, never become successful validity checks.
    """

    def register(expires_at: datetime, *, additional: dict | None = None) -> UUID:
        """Register a fresh JTI with a future, timezone-aware expiration.

        Lifetime limits belong to the issuing/verifying JWT profile. IDs are
        generated here, not supplied by callers, and must never be reused.
        Additional JSON metadata comes from trusted issuing code, is set at
        issuance, and must never override signed claims or grant permissions.
        """

    def get_active(token_id: UUID) -> IssuedJWT | None:
        """Fetch a fresh, unexpired entry including its per-issuance metadata.

        Return None for missing, expired, or revoked IDs. Like is_active, this
        requires prior signature verification and does not authorize access.
        """

    def is_active(token_id: UUID) -> bool:
        """Check freshly whether the ID exists and has not expired.

        This is not JWT verification: callers must first validate the signed
        token, then separately enforce its restrictions and live resource ACLs.
        """

    def revoke(token_id: UUID) -> None:
        """Delete the ID; missing IDs are harmless. Callers authorize revocation."""

    def delete_expired() -> int:
        """Delete entries one maximum token lifetime past expiry; return their count.

        The grace period does not extend token validity.
        """
