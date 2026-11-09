# SPDX-License-Identifier: Apache-2.0

from zope.interface import Interface

from warehouse.jwt.claims import VerifiedJWT


class IJWTVerifier(Interface):
    def verify(token: str) -> VerifiedJWT | None:
        """Verify the configured Warehouse JWT profile and return immutable claims.

        Return None for invalid tokens and propagate configuration or service
        errors. The caller enforces live authorization.
        """
