# SPDX-License-Identifier: Apache-2.0

import hmac
import json

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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
from warehouse.jwt.profile import is_uuid
from warehouse.jwt.services import (
    DisabledJWTVerifier,
)
from warehouse.jwt.verifier import (
    WarehouseJWTVerifier,
)


@pytest.mark.parametrize("value", [None, True, 1, [], {}])
def test_uuid_requires_string(value):
    # PyJWT also checks subject/JTI types; keep our canonical-ID guard independent.
    assert not is_uuid(value)


def sign_raw(payload, header, key):
    """Sign even malformed JSON claims/headers rejected by jwt.encode itself."""
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
            ("issuer", None),
            ("audience", ""),
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

    @pytest.mark.parametrize("issuer_host", ["pypi.org", "test.pypi.org"])
    @pytest.mark.parametrize("audience_host", ["pypi.org", "test.pypi.org"])
    @pytest.mark.parametrize("recipient_host", ["pypi.org", "test.pypi.org"])
    @pytest.mark.parametrize("recipient", ["api", "upload"])
    def test_environment_binding(
        self,
        clock,
        signing_keys,
        sign,
        claims,
        issuer_host,
        audience_host,
        recipient_host,
        recipient,
    ):
        # Deliberately share a key to isolate issuer/audience validation. Real
        # deployments must use separate signing keys for each environment.
        verifier = WarehouseJWTVerifier(
            issuer=f"https://{recipient_host}",
            audience=f"https://{recipient_host}/{recipient}",
            keys={"current": signing_keys[0].public_key()},
        )
        claims["iss"] = f"https://{issuer_host}"
        claims["aud"] = f"https://{audience_host}/{recipient}"
        token = sign()
        matches = issuer_host == audience_host == recipient_host
        assert (verifier.verify(token) is not None) == matches

    def test_disabled_verifier_still_rejects_signed_tokens(self, verifier, sign):
        token = sign()
        assert verifier.verify(token).subject == SubjectRef(
            SubjectKind.USER, UUID(USER_ID)
        )
        disabled = DisabledJWTVerifier()
        assert disabled.verify(token) is None

    def test_configured_key_rotation(self, clock, signing_keys, sign, headers):
        keys = {
            "current": signing_keys[0].public_key(),
            "previous": signing_keys[1].public_key(),
        }
        verifier = WarehouseJWTVerifier(issuer=ISSUER, audience=API_AUDIENCE, keys=keys)
        keys.clear()  # Caller mutation must not change the configured trust set.
        assert verifier.verify(sign()).subject == SubjectRef(
            SubjectKind.USER, UUID(USER_ID)
        )
        headers["kid"] = "previous"
        assert verifier.verify(sign(key=signing_keys[1])).subject == SubjectRef(
            SubjectKind.USER, UUID(USER_ID)
        )

    @pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "e30.e30."])
    def test_malformed_token(self, verifier, token):
        assert verifier.verify(token) is None

    def test_wrong_signature(self, verifier, sign, signing_keys):
        assert verifier.verify(sign(key=signing_keys[1])) is None

    def test_tampered_payload(self, verifier, sign, claims):
        header, _, signature = sign().split(".")
        claims["sub"] = OTHER_ID
        payload = base64url_encode(json.dumps(claims).encode()).decode()
        assert verifier.verify(f"{header}.{payload}.{signature}") is None

    @pytest.mark.parametrize("payload", [[], "not an object"])
    def test_non_object_payload(self, verifier, headers, signing_keys, payload):
        assert verifier.verify(sign_raw(payload, headers, signing_keys[0])) is None

    @pytest.mark.parametrize("field", ["alg", "typ", "kid"])
    def test_missing_header(self, verifier, headers, claims, signing_keys, field):
        del headers[field]
        assert verifier.verify(sign_raw(claims, headers, signing_keys[0])) is None

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("typ", "JWT"),
            ("typ", "id_token"),
            ("typ", None),
            ("alg", "HS256"),
            ("alg", "none"),
            ("kid", "unknown"),
            ("kid", ""),
            ("kid", []),
            ("kid", None),
            ("crit", ["custom"]),
            ("jku", "https://attacker.example/keys"),
            ("jwk", {"kty": "RSA"}),
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
        # PyJWT refuses to sign with a public key as an HMAC secret, but an
        # attacker is not constrained to using PyJWT's encoder.
        message = b".".join(
            base64url_encode(json.dumps(part).encode()) for part in (headers, claims)
        )
        signature = hmac.digest(public_bytes, message, "sha256")
        token = (message + b"." + base64url_encode(signature)).decode()
        assert verifier.verify(token) is None

    def test_other_asymmetric_algorithm(self, verifier, claims, headers):
        key = ec.generate_private_key(ec.SECP256R1())
        headers["alg"] = "ES256"
        token = jwt.encode(claims, key, algorithm="ES256", headers=headers)
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
    @pytest.mark.parametrize("missing", [False, True])
    def test_required_claim(
        self, verifier, claims, headers, signing_keys, claim, missing
    ):
        if missing:
            del claims[claim]
        else:
            claims[claim] = None
        assert verifier.verify(sign_raw(claims, headers, signing_keys[0])) is None

    @pytest.mark.parametrize(
        ("claim", "value"),
        [
            ("iss", "https://other.example"),
            ("iss", [ISSUER]),
            ("iss", None),
            ("aud", "other-api"),
            ("aud", [API_AUDIENCE]),
            ("aud", [API_AUDIENCE, "other-api"]),
            ("aud", 1),
            ("sub", "username"),
            ("sub", USER_ID.upper()),
            ("sub", USER_ID.replace("-", "")),
            ("sub", 1),
            ("sub", {}),
            ("scope", "admin"),
        ],
    )
    def test_invalid_claim(self, verifier, claims, headers, signing_keys, claim, value):
        claims[claim] = value
        assert verifier.verify(sign_raw(claims, headers, signing_keys[0])) is None

    @pytest.mark.parametrize("claim", ["iat", "exp", "nbf"])
    @pytest.mark.parametrize("value", [None, [], {}, "garbage", True, 1.5])
    def test_invalid_timestamp(self, verifier, sign, claims, claim, value):
        claims[claim] = value
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize("claim", ["iat", "exp", "nbf"])
    def test_numeric_string_timestamp(self, verifier, sign, claims, claim):
        claims[claim] = str(NOW + 300 if claim == "exp" else NOW - 60)
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        ("claim", "value", "valid"),
        [
            ("exp", NOW - 1, False),
            ("exp", NOW, False),
            ("exp", NOW + 1, True),
            ("iat", NOW, True),
            ("iat", NOW + 1, False),
            ("nbf", NOW, True),
            ("nbf", NOW + 1, False),
        ],
    )
    def test_time_bounds(self, verifier, sign, claims, claim, value, valid):
        claims[claim] = value
        assert (verifier.verify(sign()) is not None) == valid

    @pytest.mark.parametrize(
        ("lifetime", "valid"),
        [
            (-1, False),
            (0, False),
            (1, True),
            (299, True),
            (300, True),
            (301, False),
            (3600, False),
        ],
    )
    def test_maximum_lifetime(self, verifier, sign, claims, lifetime, valid):
        claims["iat"] = NOW
        claims["exp"] = NOW + lifetime
        token = sign()
        assert (verifier.verify(token) is not None) == valid

    @pytest.mark.parametrize("with_nbf", [False, True])
    def test_lifetime_is_measured_from_issuance(
        self, verifier, sign, claims, clock, with_nbf
    ):
        claims["iat"] = NOW
        claims["exp"] = NOW + 3600
        if with_nbf:
            claims["nbf"] = NOW + 3599
        token = sign()
        # Even with only one second remaining, this is still a one-hour token.
        clock.move_to(datetime.fromtimestamp(NOW + 3599, UTC))
        assert verifier.verify(token) is None

    @pytest.mark.parametrize("kind", ["organization", "project", "", 1, [], {}, None])
    def test_unknown_subject_kind(self, verifier, sign, claims, kind):
        claims["subject_kind"] = kind
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize("kind", ["user", "publisher"])
    def test_typed_subject(self, verifier, sign, claims, kind):
        claims["subject_kind"] = kind
        assert verifier.verify(sign()).subject == SubjectRef(
            SubjectKind(kind), UUID(USER_ID)
        )

    @pytest.mark.parametrize("value", ["", "*", 1, [], {}, USER_ID.upper()])
    def test_invalid_jti(self, verifier, sign, claims, value):
        claims["jti"] = value
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "details", [None, [], {}, "*", True, 1, ["api:echo"], [None], [1], [[]]]
    )
    def test_invalid_authorization_details(self, verifier, sign, claims, details):
        claims["authorization_details"] = details
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "detail",
        [
            {},
            {"type": "warehouse"},
            {"actions": ["api:echo"]},
            {"permission": "api:echo", "scope": "permission"},
        ],
    )
    def test_missing_detail_fields(self, verifier, sign, claims, detail):
        claims["authorization_details"] = [detail]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "type_", [None, True, 1, [], {}, "", "Warehouse", "unknown"]
    )
    def test_unknown_detail_type(self, verifier, sign, claims, type_):
        claims["authorization_details"] = [{"type": type_, "actions": ["api:echo"]}]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "actions",
        [
            None,
            [],
            {},
            True,
            1,
            "api:echo",
            "api:echo api:observations:add",
            ["*"],
            ["unknown"],
            ["accounts:manage"],
            [None],
            [False],
            [1],
            [[]],
            [{}],
            ["api:echo", "unknown"],
        ],
    )
    def test_invalid_actions(self, verifier, sign, claims, actions):
        claims["authorization_details"] = [{"type": "warehouse", "actions": actions}]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("locations", ["https://warehouse.example/api"]),
            ("datatypes", ["observations"]),
            ("privileges", ["observer"]),
            ("restriction", "future"),
            ("scope", "permission"),
            ("permission", "api:echo"),
            ("resource", {"kind": "project", "id": PROJECT_ID}),
        ],
    )
    @pytest.mark.parametrize("narrowed", [False, True])
    def test_unsupported_detail_fields(
        self, verifier, sign, claims, field, value, narrowed
    ):
        detail = {
            "type": "warehouse",
            "actions": ["api:observations:add"],
            field: value,
        }
        if narrowed:
            detail["identifier"] = f"project:{PROJECT_ID}"
        claims["authorization_details"] = [detail]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "identifier",
        [
            None,
            False,
            1,
            [],
            {},
            "",
            "*",
            PROJECT_ID,
            {"kind": "project", "id": PROJECT_ID},
            "project:",
            "project:*",
            f":{PROJECT_ID}",
            f"PROJECT:{PROJECT_ID}",
            f"project:{PROJECT_ID.upper()}",
            f"project:{{{PROJECT_ID}}}",
            f"project:{PROJECT_ID.replace('-', '')}",
            f"project:{PROJECT_ID}:extra",
            f"project:{PROJECT_ID}\n",
            f" project:{PROJECT_ID}",
            f"organization:{PROJECT_ID}",
            f"user:{USER_ID}",
            f"publisher:{USER_ID}",
            f"publisher-projects:{USER_ID}",
        ],
    )
    @pytest.mark.parametrize("subject_kind", ["user", "publisher"])
    def test_invalid_identifier(self, verifier, sign, claims, identifier, subject_kind):
        claims["subject_kind"] = subject_kind
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["projects:upload"],
                "identifier": identifier,
            }
        ]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize("actions", [["api:echo"], ["projects:upload", "api:echo"]])
    def test_identifier_must_apply_to_every_action(
        self, verifier, sign, claims, actions
    ):
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": actions,
                "identifier": f"project:{PROJECT_ID}",
            }
        ]
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "invalid",
        [
            {"type": "unknown", "actions": ["api:observations:add"]},
            {"type": "warehouse", "actions": ["unknown"]},
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": None,
            },
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "restriction": "future",
            },
        ],
    )
    @pytest.mark.parametrize("invalid_first", [False, True])
    def test_invalid_detail_rejects_entire_token(
        self, verifier, sign, claims, invalid, invalid_first
    ):
        details = [{"type": "warehouse", "actions": ["api:observations:add"]}, invalid]
        claims["authorization_details"] = (
            list(reversed(details)) if invalid_first else details
        )
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize("subject_kind", ["user", "publisher"])
    @pytest.mark.parametrize(
        "permission",
        [
            Permissions.ProjectsUpload,
            Permissions.APIEcho,
            Permissions.APIObservationsAdd,
        ],
    )
    def test_permission_wide_detail(
        self, verifier, sign, claims, subject_kind, permission
    ):
        claims["subject_kind"] = subject_kind
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": [permission]}
        ]
        result = verifier.verify(sign())
        assert result.authorization_details == (
            AuthorizationDetail(AuthorizationType.WAREHOUSE, (permission,)),
        )

    @pytest.mark.parametrize("narrowed", [False, True])
    def test_multiple_actions_in_one_detail(self, verifier, sign, claims, narrowed):
        actions = ["projects:upload", "api:observations:add"]
        detail = {"type": "warehouse", "actions": actions}
        if narrowed:
            detail["identifier"] = f"project:{PROJECT_ID}"
        claims["authorization_details"] = [detail]
        assert verifier.verify(sign()).authorization_details == (
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE,
                (Permissions.ProjectsUpload, Permissions.APIObservationsAdd),
                ResourceRef(ResourceKind.PROJECT, UUID(PROJECT_ID))
                if narrowed
                else None,
            ),
        )

    @pytest.mark.parametrize(
        "legacy",
        [
            {"grants": [{"permission": "api:echo", "scope": "permission"}]},
            {"permissions": ["api:echo"], "project_ids": []},
            {"scope": "api:echo"},
        ],
    )
    @pytest.mark.parametrize("with_details", [False, True])
    def test_legacy_authorization_is_not_accepted(
        self, verifier, sign, claims, legacy, with_details
    ):
        if not with_details:
            del claims["authorization_details"]
        claims.update(legacy)
        assert verifier.verify(sign()) is None

    def test_immutable_result(self, verifier, sign):
        verified = verifier.verify(sign())
        with pytest.raises(FrozenInstanceError):
            verified.audience = UPLOAD_AUDIENCE
        with pytest.raises(FrozenInstanceError):
            verified.subject.kind = SubjectKind.PUBLISHER
        with pytest.raises(FrozenInstanceError):
            verified.authorization_details[0].actions = (Permissions.APIEcho,)
        with pytest.raises(FrozenInstanceError):
            verified.authorization_details[0].resource.id = UUID(OTHER_ID)
        assert isinstance(verified.authorization_details, tuple)
        assert isinstance(verified.authorization_details[0].actions, tuple)

    @pytest.mark.parametrize(
        "error", [RuntimeError("unavailable"), jwt.InvalidKeyError()]
    )
    def test_operational_errors_propagate(self, verifier, sign, mocker, error):
        token = sign()
        mocker.patch("warehouse.jwt.verifier.jwt.decode", side_effect=error)
        with pytest.raises(type(error)):
            verifier.verify(token)
