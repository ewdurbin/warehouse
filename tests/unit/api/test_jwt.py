# SPDX-License-Identifier: Apache-2.0

import hmac
import json
import types

from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from freezegun import freeze_time
from jwt.utils import base64url_encode
from pyramid import testing
from pyramid.authorization import Allow, Authenticated
from pyramid.request import Request, apply_request_extensions
from zope.interface.verify import verifyClass

from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.jwt import JWTSecurityPolicy
from warehouse.accounts.utils import UserContext
from warehouse.api.interfaces import IJWTVerifier
from warehouse.api.jwt import WarehouseJWTVerifier
from warehouse.api.services import DisabledJWTVerifier
from warehouse.authnz import Permissions
from warehouse.packaging.models import Project
from warehouse.predicates import AuthMethodsPredicate
from warehouse.utils.security_policy import AuthenticationMethod, MultiSecurityPolicy

ISSUER = "https://warehouse.example"
API_AUDIENCE = "https://warehouse.example/api"
UPLOAD_AUDIENCE = "https://warehouse.example/upload"
USER_ID = "ddf9597e-dda1-45a2-b026-3a090ad7c4b2"
PROJECT_ID = "95ea64e2-764c-4320-a4e5-991df49f261f"
OTHER_ID = "fa604ec6-493b-4cbd-93a2-aa07883e4649"
NOW = 2_000_000_000


@pytest.fixture(scope="module")
def signing_keys():
    return [
        rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)
    ]


@pytest.fixture
def clock():
    with freeze_time(datetime.fromtimestamp(NOW, UTC), ignore=["_pytest"]) as clock:
        yield clock


@pytest.fixture
def claims():
    return {
        "iss": ISSUER,
        "aud": API_AUDIENCE,
        "sub": USER_ID,
        "iat": NOW - 60,
        "exp": NOW + 240,
        "permissions": [
            "projects:upload",
            "api:echo",
            "api:observations:add",
        ],
        "project_ids": [PROJECT_ID],
    }


@pytest.fixture
def headers():
    return {"alg": "RS256", "typ": "warehouse-api-key+jwt", "kid": "current"}


@pytest.fixture
def sign(signing_keys, claims, headers):
    def sign(payload=None, *, header=None, key=None):
        return jwt.encode(
            claims if payload is None else payload,
            signing_keys[0] if key is None else key,
            algorithm="RS256",
            headers=headers if header is None else header,
        )

    return sign


def sign_raw(payload, header, key):
    """Sign even malformed JSON claims/headers rejected by jwt.encode itself."""
    message = b".".join(
        base64url_encode(json.dumps(part).encode()) for part in (header, payload)
    )
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b"." + base64url_encode(signature)).decode()


@pytest.fixture
def expected_audience():
    return API_AUDIENCE


@pytest.fixture
def verifier(signing_keys, clock, expected_audience):
    return WarehouseJWTVerifier(
        issuer=ISSUER,
        audience=expected_audience,
        keys={"current": signing_keys[0].public_key()},
    )


@pytest.fixture
def user():
    return types.SimpleNamespace(
        id=UUID(USER_ID), __principals__=lambda: [Authenticated, f"user:{USER_ID}"]
    )


@pytest.fixture
def request_identity(user):
    return types.SimpleNamespace(identity=UserContext(user, macaroon=None))


@pytest.fixture
def project(mocker):
    return mocker.Mock(spec=Project, id=UUID(PROJECT_ID))


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
        assert verifier.verify(sign()) == USER_ID

    @pytest.mark.parametrize("issuer_host", ["pypi.org", "test.pypi.org"])
    @pytest.mark.parametrize("audience_host", ["pypi.org", "test.pypi.org"])
    @pytest.mark.parametrize("recipient_host", ["pypi.org", "test.pypi.org"])
    @pytest.mark.parametrize(
        ("recipient", "permission"),
        [("api", Permissions.APIEcho), ("upload", Permissions.ProjectsUpload)],
    )
    def test_environment_binding(
        self,
        clock,
        signing_keys,
        sign,
        claims,
        request_identity,
        project,
        issuer_host,
        audience_host,
        recipient_host,
        recipient,
        permission,
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
        assert verifier.verify(token) == (USER_ID if matches else None)
        assert verifier.permits(token, request_identity, project, permission) == matches

    def test_disabled_verifier_still_rejects_signed_tokens(self, verifier, sign):
        token = sign()
        assert verifier.verify(token) == USER_ID
        disabled = DisabledJWTVerifier()
        assert disabled.verify(token) is None
        assert not disabled.permits(token, None, None, Permissions.APIEcho)

    def test_configured_key_rotation(self, clock, signing_keys, sign, headers):
        keys = {
            "current": signing_keys[0].public_key(),
            "previous": signing_keys[1].public_key(),
        }
        verifier = WarehouseJWTVerifier(issuer=ISSUER, audience=API_AUDIENCE, keys=keys)
        keys.clear()  # Caller mutation must not change the configured trust set.
        assert verifier.verify(sign()) == USER_ID
        headers["kid"] = "previous"
        assert verifier.verify(sign(key=signing_keys[1])) == USER_ID

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
        "claim", ["iss", "aud", "sub", "iat", "exp", "permissions", "project_ids"]
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
        assert verifier.verify(sign()) == (USER_ID if valid else None)

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
    def test_maximum_lifetime(
        self, verifier, sign, claims, request_identity, lifetime, valid
    ):
        claims["iat"] = NOW
        claims["exp"] = NOW + lifetime
        token = sign()
        assert verifier.verify(token) == (USER_ID if valid else None)
        assert (
            verifier.permits(token, request_identity, None, Permissions.APIEcho)
            == valid
        )

    @pytest.mark.parametrize("with_nbf", [False, True])
    def test_lifetime_is_measured_from_issuance(
        self, verifier, sign, claims, request_identity, clock, with_nbf
    ):
        claims["iat"] = NOW
        claims["exp"] = NOW + 3600
        if with_nbf:
            claims["nbf"] = NOW + 3599
        token = sign()
        # Even with only one second remaining, this is still a one-hour token.
        clock.move_to(datetime.fromtimestamp(NOW + 3599, UTC))
        assert verifier.verify(token) is None
        assert not verifier.permits(token, request_identity, None, Permissions.APIEcho)

    @pytest.mark.parametrize(
        "permissions",
        [[], "api:echo", {}, ["*"], ["unknown"], ["accounts:manage"], [1], [[]]],
    )
    def test_invalid_permissions(self, verifier, sign, claims, permissions):
        claims["permissions"] = permissions
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "project_ids", ["*", PROJECT_ID, {}, ["*"], ["name"], [1], [[]]]
    )
    def test_invalid_project_ids(self, verifier, sign, claims, project_ids):
        claims["project_ids"] = project_ids
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize(
        "error", [RuntimeError("unavailable"), jwt.InvalidKeyError()]
    )
    def test_operational_errors_propagate(self, verifier, sign, mocker, error):
        token = sign()
        mocker.patch("warehouse.api.jwt.jwt.decode", side_effect=error)
        with pytest.raises(type(error)):
            verifier.verify(token)
        with pytest.raises(type(error)):
            verifier.permits(token, None, None, Permissions.APIEcho)

    def test_invalid_token_cannot_authorize(self, verifier):
        assert not verifier.permits("invalid", None, None, Permissions.APIEcho)

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    def test_project_scope(
        self,
        verifier,
        sign,
        request_identity,
        project,
        claims,
        expected_audience,
        permission,
    ):
        claims["aud"] = expected_audience
        token = sign()
        assert verifier.permits(token, request_identity, project, permission)
        project.id = UUID(OTHER_ID)
        assert not verifier.permits(token, request_identity, project, permission)
        project.id = UUID(PROJECT_ID)
        assert not verifier.permits(
            token, request_identity, types.SimpleNamespace(id=project.id), permission
        )
        claims["project_ids"] = []
        assert not verifier.permits(sign(), request_identity, project, permission)

    def test_echo_needs_no_project(self, verifier, sign, claims, request_identity):
        claims["permissions"] = ["api:echo"]
        claims["project_ids"] = []
        token = sign()
        assert verifier.verify(token) == USER_ID
        assert verifier.permits(token, request_identity, None, Permissions.APIEcho)

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    def test_missing_permission(
        self,
        verifier,
        sign,
        claims,
        request_identity,
        project,
        expected_audience,
        permission,
    ):
        claims["aud"] = expected_audience
        claims["permissions"] = ["api:echo"]
        assert not verifier.permits(sign(), request_identity, project, permission)

    @pytest.mark.parametrize("permission", [Permissions.AccountManage, "api:echo", "*"])
    def test_unsupported_permission(self, verifier, sign, request_identity, permission):
        assert not verifier.permits(sign(), request_identity, None, permission)

    @pytest.mark.parametrize("identity", [None, types.SimpleNamespace()])
    def test_missing_user_identity(self, verifier, sign, request_identity, identity):
        request_identity.identity = identity
        assert not verifier.permits(sign(), request_identity, None, Permissions.APIEcho)

    def test_wrong_user(self, verifier, sign, request_identity):
        request_identity.identity.user.id = UUID(OTHER_ID)
        assert not verifier.permits(sign(), request_identity, None, Permissions.APIEcho)

    def test_macaroon_identity(self, verifier, sign, request_identity):
        request_identity.identity.macaroon = object()
        assert not verifier.permits(sign(), request_identity, None, Permissions.APIEcho)


class TestSignedJWTPolicy:
    @pytest.fixture
    def jwt_request(self, verifier, user, sign, mocker):
        user_service = mocker.Mock(spec=["get_user", "is_disabled"])
        user_service.get_user.return_value = user
        user_service.is_disabled.return_value = (False, None)
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service(verifier, IJWTVerifier)
            config.register_service(user_service, IUserService)
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/danger-api/echo")
            request.registry = config.registry
            apply_request_extensions(request)
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"api-key"}, None)]
            )
            request.headers["Authorization"] = f"Bearer {sign()}"
            yield request

    @pytest.mark.parametrize("principal", [f"user:{USER_ID}", "user:someone-else"])
    def test_live_acl_is_required(self, jwt_request, principal, user):
        context = types.SimpleNamespace(
            __acl__=[(Allow, principal, Permissions.APIEcho)]
        )
        assert jwt_request.identity == UserContext(user, macaroon=None)
        assert jwt_request.authentication_method == AuthenticationMethod.API_KEY
        assert bool(jwt_request.has_permission(Permissions.APIEcho, context)) == (
            principal == f"user:{USER_ID}"
        )

    def test_rechecks_expiration(self, jwt_request, clock, claims):
        assert jwt_request.identity is not None
        clock.move_to(datetime.fromtimestamp(claims["exp"], UTC))
        context = types.SimpleNamespace(
            __acl__=[(Allow, f"user:{USER_ID}", Permissions.APIEcho)]
        )
        result = jwt_request.has_permission(Permissions.APIEcho, context)
        assert not result
        assert result.reason == "invalid_api_key"

    def test_overlong_token_does_not_authenticate(self, jwt_request, sign, claims):
        claims["exp"] = claims["iat"] + 301
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.identity is None
        context = types.SimpleNamespace(
            __acl__=[(Allow, f"user:{USER_ID}", Permissions.APIEcho)]
        )
        assert not jwt_request.has_permission(Permissions.APIEcho, context)

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIEcho),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    @pytest.mark.parametrize(
        "token_audience",
        [API_AUDIENCE, UPLOAD_AUDIENCE, [API_AUDIENCE, UPLOAD_AUDIENCE]],
    )
    def test_recipient_audience_is_required(
        self,
        jwt_request,
        sign,
        claims,
        project,
        expected_audience,
        permission,
        token_audience,
    ):
        # Each recipient gets its own configured verifier. Even a token with
        # all supported permissions and a granting ACL cannot cross audiences.
        claims["aud"] = token_audience
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [(Allow, f"user:{USER_ID}", permission)]
        matches = token_audience == expected_audience
        assert (jwt_request.identity is not None) == matches
        assert bool(jwt_request.has_permission(permission, project)) == matches

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIEcho),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    @pytest.mark.parametrize("granted", [False, True])
    def test_matching_audience_still_requires_permission(
        self, jwt_request, sign, claims, project, expected_audience, permission, granted
    ):
        claims["aud"] = expected_audience
        claims["permissions"] = (
            [permission]
            if granted
            else [p for p in claims["permissions"] if p != permission]
        )
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [(Allow, f"user:{USER_ID}", permission)]
        assert jwt_request.identity is not None
        assert bool(jwt_request.has_permission(permission, project)) == granted

    @pytest.mark.parametrize(
        ("expected_audience", "permission"),
        [
            (UPLOAD_AUDIENCE, Permissions.ProjectsUpload),
            (API_AUDIENCE, Permissions.APIObservationsAdd),
        ],
    )
    @pytest.mark.parametrize("scoped", [False, True])
    def test_project_scope_cannot_be_bypassed_by_acl(
        self, jwt_request, sign, claims, project, expected_audience, permission, scoped
    ):
        claims["aud"] = expected_audience
        claims["project_ids"] = [PROJECT_ID] if scoped else [OTHER_ID]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [(Allow, f"user:{USER_ID}", permission)]
        assert bool(jwt_request.has_permission(permission, project)) == scoped
