# SPDX-License-Identifier: Apache-2.0

from zope.interface import Interface

from warehouse.jwt.claims import VerifiedJWT


class IJWTVerifier(Interface):
    def verify(token: str) -> VerifiedJWT | None:
        """Verify the token and return its immutable claims.

        Use the configured issuer, audience, algorithm, and public keys. Check
        the signature, token type, required claims, and validity window. Reject
        unknown claims and unsupported subjects or authorization details. An
        omitted identifier leaves the resource unrestricted by the token.
        An invalid identifier invalidates the token.

        Return None for invalid tokens. Raise on configuration or service errors.

        After verification, the caller checks the registry and resolves the
        subject. At authorization time, the caller verifies the token and checks
        the registry again, even with a cached identity. The caller also checks
        the subject against that identity, the allowed authentication methods,
        the authorization details, and the resource ACL.
        """
