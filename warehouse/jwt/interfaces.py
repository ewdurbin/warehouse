# SPDX-License-Identifier: Apache-2.0

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

        Select the expected issuer and audience from trusted server-side
        configuration, not from token claims.

        This performs no database lookups or resource authorization. Callers must
        check registry liveness, resolve the typed subject and its current status,
        and enforce authorization details, the method allowlist, and live ACLs.
        Reverify and recheck registry liveness at authorization time, even when
        request identity is cached; the resolved identity must still match the
        verified subject kind and ID.
        """
