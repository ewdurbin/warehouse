# SPDX-License-Identifier: Apache-2.0

from zope.interface import implementer

from warehouse.api.interfaces import IJWTVerifier


@implementer(IJWTVerifier)
class DisabledJWTVerifier:
    """Reject all JWTs while JWT authentication is disabled."""

    @classmethod
    def create_service(cls, context, request):
        return cls()

    def verify(self, token: str) -> str | None:
        return None

    def permits(self, token: str, request, context, permission) -> bool:
        return False
