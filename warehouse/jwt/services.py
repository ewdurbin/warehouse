# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

from pyramid.settings import asbool
from sqlalchemy import delete, exists, select
from zope.interface import implementer

from warehouse.jwt.claims import AuthorizationDetail, SignedJWT, SubjectRef, VerifiedJWT
from warehouse.jwt.interfaces import IJWTIssuer, IJWTRegistry, IJWTVerifier
from warehouse.jwt.issuer import WarehouseJWTIssuerFactory
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import MAX_LIFETIME_SECONDS


def jwt_verifier_factory(settings, *, audience=None):
    """Select the JWT verifier factory from trusted settings."""
    if not asbool(settings.get("warehouse.jwt.enabled", False)):
        return DisabledJWTVerifier.create_service

    # The verifier factory also imports DisabledJWTVerifier from this module.
    from warehouse.jwt.verifier import WarehouseJWTVerifierFactory  # noqa: PLC0415

    factory = WarehouseJWTVerifierFactory(settings)
    return factory if audience is None else factory.for_audience(audience)


def jwt_issuer_factory(settings):
    """Keep signing opt-in; verification-only deployments need no private key."""
    if not asbool(settings.get("warehouse.jwt.enabled", False)) or not any(
        name in settings
        for name in ("warehouse.jwt.signing_key", "warehouse.jwt.signing_key_id")
    ):
        return DisabledJWTIssuer.create_service

    return WarehouseJWTIssuerFactory.from_settings(settings)


@implementer(IJWTIssuer)
class DisabledJWTIssuer:
    enabled = False

    @classmethod
    def create_service(cls, context, request):
        return cls()

    def issue(
        self,
        *,
        subject: SubjectRef,
        audience: str,
        authorization_details: tuple[AuthorizationDetail, ...],
        lifetime: int = MAX_LIFETIME_SECONDS,
        additional: dict | None = None,
    ) -> SignedJWT:
        raise RuntimeError("JWT issuance is disabled")


@implementer(IJWTVerifier)
class DisabledJWTVerifier:
    """Reject all JWTs while JWT authentication is disabled."""

    @classmethod
    def create_service(cls, context, request):
        return cls()

    def verify(self, token: str) -> VerifiedJWT | None:
        return None


@implementer(IJWTRegistry)
class DatabaseJWTRegistry:
    def __init__(self, db_session):
        self.db = db_session

    @classmethod
    def create_service(cls, context, request):
        return cls(request.db)

    def register(self, expires_at: datetime, *, additional: dict | None = None) -> UUID:
        if expires_at.utcoffset() is None:
            raise ValueError("JWT expiration must be timezone-aware")
        expires_at = expires_at.astimezone(UTC)
        if expires_at <= datetime.now(UTC):
            raise ValueError("JWT expiration must be in the future")
        if additional is not None and not isinstance(additional, dict):
            raise ValueError("JWT metadata must be a dictionary")

        # Assign before insertion so the issuer can build the JWT without an
        # explicit flush. The caller must commit before handing out the token.
        token = IssuedJWT(
            id=uuid7(), expires_at=expires_at, additional=deepcopy(additional or {})
        )
        self.db.add(token)
        return token.id

    def get_active(self, token_id: UUID) -> IssuedJWT | None:
        # Always query, even if this row is already in the ORM identity map.
        return self.db.scalar(
            select(IssuedJWT)
            .where(
                IssuedJWT.id == token_id,
                IssuedJWT.expires_at > datetime.now(UTC),
            )
            .execution_options(populate_existing=True)
        )

    def is_active(self, token_id: UUID) -> bool:
        # Do not use Session.get(): an ORM identity-map hit could hide revocation
        # committed by another request. READ COMMITTED sees a fresh snapshot.
        return bool(
            self.db.scalar(
                select(
                    exists().where(
                        IssuedJWT.id == token_id,
                        IssuedJWT.expires_at > datetime.now(UTC),
                    )
                )
            )
        )

    def revoke(self, token_id: UUID) -> None:
        self.db.execute(
            delete(IssuedJWT)
            .where(IssuedJWT.id == token_id)
            .execution_options(synchronize_session=False)
        )

    def delete_expired(self) -> int:
        # Retain expired entries for one maximum token lifetime before cleanup.
        cutoff = datetime.now(UTC) - timedelta(seconds=MAX_LIFETIME_SECONDS)
        result = self.db.execute(
            delete(IssuedJWT)
            .where(IssuedJWT.expires_at <= cutoff)
            .execution_options(synchronize_session=False)
        )
        return result.rowcount
