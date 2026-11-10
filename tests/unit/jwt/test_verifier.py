# SPDX-License-Identifier: Apache-2.0

import hmac
import json

from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.utils import base64url_encode
from zope.interface.verify import verifyClass

from tests.common.jwt import (
    API_AUDIENCE,
    ISSUER,
    JTI,
    NOW,
    OTHER_ID,
    PROJECT_ID,
    UPLOAD_AUDIENCE,
    USER_ID,
)
from warehouse.authnz import Permissions
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
    SubjectKind,
    SubjectRef,
    VerifiedJWT,
)
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.profile import MAX_TOKEN_LENGTH
from warehouse.jwt.verifier import WarehouseJWTVerifier


def sign_raw(payload, header, key):
    """Sign test inputs that jwt.encode would reject before verification."""
    message = b".".join(
        base64url_encode(json.dumps(part).encode()) for part in (header, payload)
    )
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b"." + base64url_encode(signature)).decode()


class TestWarehouseJWTVerifier:
    def test_interface(self):
        assert verifyClass(IJWTVerifier, WarehouseJWTVerifier)

    @pytest.mark.parametrize(
        ("setting", "value"),
        [
            ("issuer", ""),
            ("audience", [API_AUDIENCE]),
            ("keys", {}),
            ("keys", {"": None}),
            ("keys", {1: None}),
            ("keys", {"current": "not a public key"}),
        ],
    )
    def test_invalid_configuration(self, setting, value, signing_keys):
        config = {
            "issuer": ISSUER,
            "audience": API_AUDIENCE,
            "keys": {"current": signing_keys[0].public_key()},
        }
        config[setting] = value
        with pytest.raises(ValueError, match="JWT"):
            WarehouseJWTVerifier(**config)

    def test_rejects_weak_key(self):
        # Deliberately insecure: configuration must reject this key.
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
        with pytest.raises(ValueError, match="RSA public keys >= 2048 bits"):
            WarehouseJWTVerifier(
                issuer=ISSUER, audience=API_AUDIENCE, keys={"current": key.public_key()}
            )

    def test_rejects_private_key(self, signing_keys):
        with pytest.raises(ValueError, match="RSA public keys"):
            WarehouseJWTVerifier(
                issuer=ISSUER, audience=API_AUDIENCE, keys={"current": signing_keys[0]}
            )

    def test_valid_token(self, verifier, sign):
        assert verifier.verify(sign()) == VerifiedJWT(
            jti=UUID(JTI),
            subject=SubjectRef(SubjectKind.USER, UUID(USER_ID)),
            issuer=ISSUER,
            audience=API_AUDIENCE,
            issued_at=datetime.fromtimestamp(NOW - 60, UTC),
            expires_at=datetime.fromtimestamp(NOW + 240, UTC),
            authorization_details=(
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.ProjectsUpload,),
                    ResourceRef(ResourceKind.PROJECT, UUID(PROJECT_ID)),
                ),
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE, (Permissions.APIEcho,)
                ),
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.APIObservationsAdd,),
                    ResourceRef(ResourceKind.PROJECT, UUID(PROJECT_ID)),
                ),
            ),
        )

    def test_publisher_subject(self, verifier, sign, claims):
        claims["subject_kind"] = "publisher"
        assert verifier.verify(sign()).subject == SubjectRef(
            SubjectKind.PUBLISHER, UUID(USER_ID)
        )

    def test_configured_key_rotation(self, clock, signing_keys, sign, headers):
        keys = {
            "current": signing_keys[0].public_key(),
            "previous": signing_keys[1].public_key(),
        }
        verifier = WarehouseJWTVerifier(issuer=ISSUER, audience=API_AUDIENCE, keys=keys)
        keys.clear()  # Caller mutation must not change the configured trust set.
        assert verifier.verify(sign()) is not None
        headers["kid"] = "previous"
        assert verifier.verify(sign(key=signing_keys[1])) is not None

    @pytest.mark.parametrize("token", ["garbage", "a.b.c"])
    def test_malformed_token(self, verifier, token):
        assert verifier.verify(token) is None

    def test_oversized_token_rejected_before_parsing(
        self, verifier, sign, claims, mocker
    ):
        claims["authorization_details"] *= 100
        token = sign()
        assert len(token) > MAX_TOKEN_LENGTH

        get_header = mocker.spy(jwt, "get_unverified_header")
        assert verifier.verify(token) is None
        get_header.assert_not_called()

    @pytest.mark.parametrize(
        "suffix",
        [pytest.param("==", id="padding"), pytest.param("\ud800", id="non-ascii")],
    )
    def test_rejects_noncompact_encoding(self, verifier, sign, suffix):
        assert verifier.verify(sign() + suffix) is None

    def test_wrong_signature(self, verifier, sign, signing_keys):
        assert verifier.verify(sign(key=signing_keys[1])) is None

    def test_tampered_payload(self, verifier, sign, claims):
        header, _, signature = sign().split(".")
        claims["sub"] = OTHER_ID
        payload = base64url_encode(json.dumps(claims).encode()).decode()
        assert verifier.verify(f"{header}.{payload}.{signature}") is None

    def test_non_object_payload(self, verifier, headers, signing_keys):
        assert verifier.verify(sign_raw([], headers, signing_keys[0])) is None

    @pytest.mark.parametrize("field", ["alg", "typ", "kid"])
    def test_missing_header(self, verifier, headers, claims, signing_keys, field):
        del headers[field]
        assert verifier.verify(sign_raw(claims, headers, signing_keys[0])) is None

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("typ", "JWT"),
            ("typ", "warehouse-api-key+jwt"),
            ("kid", "unknown"),
            ("kid", []),
            ("crit", ["custom"]),
            ("jku", "https://other.example/keys"),
        ],
    )
    def test_invalid_header(
        self, verifier, headers, claims, signing_keys, field, value
    ):
        headers[field] = value
        assert verifier.verify(sign_raw(claims, headers, signing_keys[0])) is None

    def test_unsigned_token(self, verifier, claims, headers):
        headers["alg"] = "none"
        token = jwt.encode(claims, None, algorithm="none", headers=headers)
        assert verifier.verify(token) is None

    def test_algorithm_confusion(self, verifier, claims, headers, signing_keys):
        public_bytes = (
            signing_keys[0]
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        headers["alg"] = "HS256"
        # Build the signature directly to bypass PyJWT's check against using
        # a public key as an HMAC secret.
        message = b".".join(
            base64url_encode(json.dumps(part).encode()) for part in (headers, claims)
        )
        signature = hmac.digest(public_bytes, message, "sha256")
        token = (message + b"." + base64url_encode(signature)).decode()
        assert verifier.verify(token) is None

    @pytest.mark.parametrize(
        "claim",
        [
            "iss",
            "aud",
            "sub",
            "subject_kind",
            "jti",
            "iat",
            "exp",
            "authorization_details",
        ],
    )
    def test_missing_required_claim(self, verifier, claims, sign, claim):
        del claims[claim]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        ("claim", "value"),
        [
            ("iss", "https://other.example"),
            ("aud", UPLOAD_AUDIENCE),
            ("aud", [API_AUDIENCE]),
            ("sub", USER_ID.upper()),
            ("jti", JTI.upper()),
            ("subject_kind", "organization"),
            ("iat", NOW - 59.5),
            ("exp", str(NOW + 240)),
            ("nbf", True),
            ("scope", "admin"),
        ],
    )
    def test_invalid_claim(self, verifier, claims, sign, claim, value):
        claims[claim] = value
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        ("claim", "value"), [("exp", NOW), ("iat", NOW + 1), ("nbf", NOW + 1)]
    )
    def test_outside_validity_window(self, verifier, sign, claims, claim, value):
        claims[claim] = value
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(("lifetime", "valid"), [(300, True), (301, False)])
    def test_maximum_lifetime(self, verifier, sign, claims, lifetime, valid):
        claims["iat"] = NOW
        claims["exp"] = NOW + lifetime
        assert (verifier.verify(sign()) is not None) is valid

    def test_delayed_not_before_does_not_extend_lifetime(self, verifier, sign, claims):
        claims["iat"] = NOW - 61
        claims["nbf"] = NOW - 1
        assert verifier.verify(sign()) is None

    def test_invalid_detail_rejects_entire_token(self, verifier, sign, claims):
        claims["authorization_details"].append(
            {"type": "warehouse", "actions": ["projects:upload"], "identifier": None}
        )
        assert verifier.verify(sign()) is None

    def test_operational_error_propagates(self, verifier, sign, mocker):
        token = sign()
        mocker.patch(
            "warehouse.jwt.verifier.jwt.decode", side_effect=jwt.InvalidKeyError
        )
        with pytest.raises(jwt.InvalidKeyError):
            verifier.verify(token)
