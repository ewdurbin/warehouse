# SPDX-License-Identifier: Apache-2.0

from pyramid.settings import asbool
from zope.interface import implementer

from warehouse.api.interfaces import IJWTVerifier


def jwt_verifier_factory(settings):
    """Configure the request factory once, keeping JWT authentication opt-in."""
    if not asbool(settings.get("warehouse.jwt.enabled", False)):
        return DisabledJWTVerifier.create_service

    # Avoid importing account/packaging models while accounts is being imported.
    from warehouse.api.jwt import WarehouseJWTVerifierFactory  # noqa: PLC0415

    return WarehouseJWTVerifierFactory(settings)


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
