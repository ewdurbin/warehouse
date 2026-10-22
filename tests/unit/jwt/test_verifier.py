# SPDX-License-Identifier: Apache-2.0

import base64
import hmac
import json
import types

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from freezegun import freeze_time
from jwt.utils import base64url_encode
from pyramid import testing
from pyramid.authorization import Allow, Authenticated
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import IRoutesMapper
from pyramid.request import Request, apply_request_extensions
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from zope.interface.verify import verifyClass

from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory, RoleFactory
from warehouse.accounts import _oidc_claims, _oidc_publisher, _user
from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
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
from warehouse.jwt.interfaces import IJWTRegistry, IJWTVerifier
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.profile import is_uuid
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.jwt.services import (
    DatabaseJWTRegistry,
    DisabledJWTVerifier,
    jwt_verifier_factory,
)
from warehouse.jwt.verifier import (
    WarehouseJWTVerifier,
    WarehouseJWTVerifierFactory,
)
from warehouse.oidc.utils import PublisherTokenContext
from warehouse.packaging.models import LifecycleStatus, Project
from warehouse.predicates import AuthMethodsPredicate, JWTAudiencePredicate
from warehouse.routes import includeme as include_routes
from warehouse.utils.security_policy import AuthenticationMethod, MultiSecurityPolicy

ISSUER = "https://warehouse.example"
API_AUDIENCE = "https://warehouse.example/api"
UPLOAD_AUDIENCE = "https://warehouse.example/upload"
USER_ID = "ddf9597e-dda1-45a2-b026-3a090ad7c4b2"
PROJECT_ID = "95ea64e2-764c-4320-a4e5-991df49f261f"
OTHER_ID = "fa604ec6-493b-4cbd-93a2-aa07883e4649"
JTI = "0199c0f2-4b00-7000-8000-000000000001"
NOW = 2_000_000_000


@pytest.mark.parametrize("value", [None, True, 1, [], {}])
def test_uuid_requires_string(value):
    # PyJWT also checks subject/JTI types; keep our canonical-ID guard independent.
    assert not is_uuid(value)


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
        "subject_kind": "user",
        "jti": JTI,
        "iat": NOW - 60,
        "exp": NOW + 240,
        "authorization_details": [
            {
                "type": "warehouse",
                "actions": ["projects:upload"],
                "identifier": f"project:{PROJECT_ID}",
            },
            {"type": "warehouse", "actions": ["api:echo"]},
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{PROJECT_ID}",
            },
        ],
    }


@pytest.fixture
def registered_jti(jwt_registry, clock, claims):
    token_id = jwt_registry.register(datetime.fromtimestamp(claims["exp"], UTC))
    claims["jti"] = str(token_id)
    return token_id


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
def project(mocker):
    return mocker.Mock(spec=Project, id=UUID(PROJECT_ID))


@pytest.fixture
def jwt_settings(signing_keys):
    return {
        "warehouse.jwt.enabled": True,
        "warehouse.jwt.issuer": ISSUER,
        "warehouse.jwt.upload_audience": UPLOAD_AUDIENCE,
        "warehouse.jwt.api_audience": API_AUDIENCE,
        "warehouse.jwt.verification_keys": {
            kid: key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
            for kid, key in zip(("current", "previous"), signing_keys, strict=True)
        },
    }


class TestWarehouseJWTVerifierFactory:
    def test_enabled_without_configuration(self):
        with pytest.raises(ConfigurationError):
            jwt_verifier_factory({"warehouse.jwt.enabled": True})

    @pytest.mark.parametrize(
        "setting",
        ["issuer", "upload_audience", "api_audience", "verification_keys"],
    )
    def test_missing_setting(self, jwt_settings, setting):
        del jwt_settings[f"warehouse.jwt.{setting}"]
        with pytest.raises(ConfigurationError, match=r"JWT|warehouse\.jwt"):
            jwt_verifier_factory(jwt_settings)

    @pytest.mark.parametrize(
        ("setting", "value"),
        [
            ("issuer", ""),
            ("issuer", [ISSUER]),
            ("upload_audience", ""),
            ("api_audience", ""),
            ("api_audience", [API_AUDIENCE]),
            ("api_audience", UPLOAD_AUDIENCE),
            ("verification_keys", {}),
            ("verification_keys", []),
            ("verification_keys", "not a mapping"),
            ("verification_keys", {"current": None}),
            ("verification_keys", {"current": "not PEM"}),
        ],
    )
    def test_invalid_setting(self, jwt_settings, setting, value):
        jwt_settings[f"warehouse.jwt.{setting}"] = value
        with pytest.raises(ConfigurationError, match=r"JWT|warehouse\.jwt"):
            jwt_verifier_factory(jwt_settings)

    @pytest.mark.parametrize("kid", ["", 1])
    def test_invalid_key_id(self, jwt_settings, kid):
        keys = jwt_settings["warehouse.jwt.verification_keys"]
        jwt_settings["warehouse.jwt.verification_keys"] = {kid: keys["current"]}
        with pytest.raises(ConfigurationError, match="key IDs"):
            jwt_verifier_factory(jwt_settings)

    def test_private_key(self, jwt_settings, signing_keys):
        jwt_settings["warehouse.jwt.verification_keys"]["current"] = (
            signing_keys[0]
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        with pytest.raises(ConfigurationError, match="PEM public key"):
            jwt_verifier_factory(jwt_settings)

    @pytest.mark.parametrize("kind", ["ec", "weak-rsa"])
    def test_unsuitable_public_key(self, jwt_settings, kind):
        if kind == "ec":
            key = ec.generate_private_key(ec.SECP256R1())
        else:
            # Deliberately insecure: startup must reject this key.
            key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
        jwt_settings["warehouse.jwt.verification_keys"]["current"] = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        with pytest.raises(ConfigurationError, match="RSA public keys >= 2048 bits"):
            jwt_verifier_factory(jwt_settings)

    def test_unsupported_key_algorithm(self, jwt_settings, mocker):
        mocker.patch(
            "warehouse.jwt.verifier.load_pem_public_key",
            side_effect=UnsupportedAlgorithm("Unsupported key algorithm"),
        )
        with pytest.raises(ConfigurationError, match="PEM public key"):
            jwt_verifier_factory(jwt_settings)

    def test_loads_keys_once(self, jwt_settings, mocker, clock, sign):
        load = mocker.patch(
            "warehouse.jwt.verifier.load_pem_public_key",
            wraps=serialization.load_pem_public_key,
        )
        factory = jwt_verifier_factory(jwt_settings)
        assert isinstance(factory, WarehouseJWTVerifierFactory)
        assert load.call_count == 2
        request = testing.DummyRequest()
        request.matched_route = types.SimpleNamespace(
            name="api.echo",
            predicates=[
                AuthMethodsPredicate({"api-key"}, None),
                JWTAudiencePredicate("api", None),
            ],
        )
        # Configuration is snapshotted at startup, never read from the request.
        jwt_settings["warehouse.jwt.verification_keys"].clear()
        jwt_settings["warehouse.jwt.api_audience"] = UPLOAD_AUDIENCE
        verifier = factory(None, request)
        assert factory(None, request) is verifier
        assert verifier.verify(sign()).subject == SubjectRef(
            SubjectKind.USER, UUID(USER_ID)
        )
        assert load.call_count == 2

    @pytest.mark.parametrize(
        "route_name",
        [
            None,
            "api.echo",
            "forklift.legacy.file_upload",
            "api.unknown",
            "api.echo.attacker",
            "forklift.legacy.submit",
            "manage.account",
        ],
    )
    def test_missing_audience(self, jwt_settings, route_name, clock, sign):
        request = testing.DummyRequest()
        request.matched_route = (
            types.SimpleNamespace(
                name=route_name, predicates=[AuthMethodsPredicate({"api-key"}, None)]
            )
            if route_name is not None
            else None
        )
        verifier = jwt_verifier_factory(jwt_settings)(None, request)
        assert isinstance(verifier, DisabledJWTVerifier)
        assert verifier.verify(sign()) is None

    @pytest.mark.parametrize("methods", [None, set(), {"macaroon"}])
    def test_route_requires_api_key_opt_in(self, jwt_settings, methods):
        request = testing.DummyRequest()
        request.matched_route = types.SimpleNamespace(
            name="api.echo",
            predicates=[JWTAudiencePredicate("api", None)]
            + ([] if methods is None else [AuthMethodsPredicate(methods, None)]),
        )
        assert isinstance(
            jwt_verifier_factory(jwt_settings)(None, request), DisabledJWTVerifier
        )


@pytest.fixture
def jwt_enabled():
    return True


@pytest.fixture
def make_request(
    jwt_settings, jwt_enabled, user, mocker, clock, registered_jti, db_session
):
    jwt_settings.pop("warehouse.jwt.enabled")
    if jwt_enabled is not None:
        jwt_settings["warehouse.jwt.enabled"] = jwt_enabled
    user_service = mocker.Mock(spec=["get_user", "is_disabled"])
    user_service.get_user.return_value = user
    user_service.is_disabled.return_value = (False, None)
    jwt_settings.update(
        {
            "docs.url": "https://docs.example",
            "files.url": "https://files.example/{path}",
        }
    )
    with testing.testConfig(settings=jwt_settings) as config:
        config.include("pyramid_services")
        config.include("warehouse.predicates")
        config.include("warehouse.legacy.action_routing")
        config.include("warehouse.forklift")
        # Install the application's actual add_route declarations without
        # unrelated redirect/template/XML-RPC view configuration.
        route_config = mocker.Mock()
        route_config.get_settings.return_value = config.get_settings()
        route_config.registry = config.registry
        route_config.add_route = config.add_route
        include_routes(route_config)
        for audience_name in ("api", "upload"):
            config.add_route(
                f"new-endpoint.{audience_name}",
                f"/audience-test/{audience_name}",
                auth_methods={"api-key"},
                jwt_audience=audience_name,
            )
        config.add_directive("add_periodic_task", mocker.Mock())
        config.include("warehouse.jwt")
        config.register_service(user_service, IUserService)
        config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
        config.commit()
        mapper = config.registry.getUtility(IRoutesMapper)

        def make_request(path, token):
            request = Request.blank(path)
            request.registry = config.registry
            apply_request_extensions(request)
            request.db = db_session
            request.headers["Authorization"] = f"Bearer {token}"
            match = mapper(request)
            request.matched_route = match["route"]
            request.matchdict = match["match"]
            return request

        yield make_request


class TestAudienceJWTService:
    @pytest.mark.parametrize(
        ("path", "route_name", "audience", "permission"),
        [
            (
                "/legacy/?:action=file_upload",
                "forklift.legacy.file_upload",
                UPLOAD_AUDIENCE,
                Permissions.ProjectsUpload,
            ),
            ("/danger-api/echo", "api.echo", API_AUDIENCE, Permissions.APIEcho),
            (
                "/danger-api/projects/example/observations",
                "api.projects.observations",
                API_AUDIENCE,
                Permissions.APIObservationsAdd,
            ),
        ],
    )
    @pytest.mark.parametrize(
        "token_audience",
        [API_AUDIENCE, UPLOAD_AUDIENCE, [API_AUDIENCE, UPLOAD_AUDIENCE]],
    )
    @pytest.mark.parametrize("kid", ["current", "previous"])
    def test_audience_binding(
        self,
        make_request,
        sign,
        claims,
        headers,
        signing_keys,
        user,
        project,
        path,
        route_name,
        audience,
        permission,
        token_audience,
        kid,
    ):
        claims["aud"] = token_audience
        headers["kid"] = kid
        token = sign(key=signing_keys[0 if kid == "current" else 1])
        request = make_request(path, token)
        assert request.matched_route.name == route_name
        project.__acl__ = [(Allow, f"user:{USER_ID}", permission)]
        accepted = token_audience == audience
        assert request.identity == (
            UserContext(user, macaroon=None) if accepted else None
        )
        assert bool(request.has_permission(permission, project)) == accepted
        if accepted:
            assert request.authentication_method == AuthenticationMethod.API_KEY

    @pytest.mark.parametrize("jwt_enabled", [None, False, "false"])
    def test_disabled_by_default(self, make_request, sign):
        # Having valid keys alone must not enable JWTs.
        request = make_request("/danger-api/echo", sign())
        assert isinstance(
            request.find_service(IJWTVerifier, context=None), DisabledJWTVerifier
        )
        assert request.identity is None

    @pytest.mark.parametrize(
        ("audience_name", "audience"),
        [("api", API_AUDIENCE), ("upload", UPLOAD_AUDIENCE)],
    )
    @pytest.mark.parametrize("token_audience", [API_AUDIENCE, UPLOAD_AUDIENCE])
    def test_new_routes_need_no_verifier_changes(
        self, make_request, sign, claims, audience_name, audience, token_audience
    ):
        claims["aud"] = token_audience
        request = make_request(f"/audience-test/{audience_name}", sign())
        assert request.matched_route.name == f"new-endpoint.{audience_name}"
        assert (request.identity is not None) == (token_audience == audience)

    def test_audiences_do_not_change_each_others_verifier(
        self, make_request, sign, claims, project
    ):
        api_request = make_request("/danger-api/echo", sign())
        claims["aud"] = UPLOAD_AUDIENCE
        upload_request = make_request("/legacy/?:action=file_upload", sign())
        assert api_request.identity is not None
        assert upload_request.identity is not None
        project.__acl__ = [
            (
                Allow,
                f"user:{USER_ID}",
                [Permissions.APIEcho, Permissions.ProjectsUpload],
            )
        ]
        assert api_request.has_permission(Permissions.APIEcho, project)
        assert upload_request.has_permission(Permissions.ProjectsUpload, project)
        assert api_request.has_permission(Permissions.APIEcho, project)

    @pytest.mark.parametrize(
        "matched_path", ["/danger-api/echo", "/legacy/?:action=file_upload"]
    )
    def test_untrusted_request_fields_cannot_choose_audience(
        self, make_request, sign, claims, matched_path
    ):
        claims["aud"] = (
            UPLOAD_AUDIENCE if matched_path.startswith("/danger-api") else API_AUDIENCE
        )
        request = make_request(matched_path, sign())
        # Once routing is resolved, even hostile request metadata cannot select
        # the other verifier. Real routing is tested separately above.
        request.host = "attacker.example"
        request.path_info = (
            "/legacy/" if matched_path.startswith("/danger-api") else "/danger-api/echo"
        )
        request.query_string = f"aud={claims['aud']}&jwt_audience=api"
        request.headers["X-Forwarded-Host"] = "attacker.example"
        request.headers["X-JWT-Audience"] = claims["aud"]
        assert request.identity is None


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


class TestSignedJWTPolicy:
    @pytest.fixture
    def jwt_request(self, verifier, user, sign, mocker, jwt_registry, registered_jti):
        user_service = mocker.Mock(spec=["get_user", "is_disabled"])
        user_service.get_user.return_value = user
        user_service.is_disabled.return_value = (False, None)
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service(verifier, IJWTVerifier)
            config.register_service(jwt_registry, IJWTRegistry)
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
        claims["authorization_details"] = [
            detail
            for detail in claims["authorization_details"]
            if (permission in detail["actions"]) == granted
        ]
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
        for detail in claims["authorization_details"]:
            if "identifier" in detail:
                detail["identifier"] = f"project:{PROJECT_ID if scoped else OTHER_ID}"
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [(Allow, f"user:{USER_ID}", permission)]
        assert bool(jwt_request.has_permission(permission, project)) == scoped

    def test_permission_resource_pairs_do_not_cross(
        self, jwt_request, claims, sign, project
    ):
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["projects:upload"],
                "identifier": f"project:{PROJECT_ID}",
            },
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{OTHER_ID}",
            },
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [
            (
                Allow,
                f"user:{USER_ID}",
                [Permissions.ProjectsUpload, Permissions.APIObservationsAdd],
            )
        ]
        assert jwt_request.has_permission(Permissions.ProjectsUpload, project)
        assert not jwt_request.has_permission(Permissions.APIObservationsAdd, project)
        project.id = UUID(OTHER_ID)
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, project)
        assert jwt_request.has_permission(Permissions.APIObservationsAdd, project)

    def test_multiple_actions_share_one_identifier(
        self, jwt_request, claims, sign, project
    ):
        permissions = [Permissions.ProjectsUpload, Permissions.APIObservationsAdd]
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": permissions,
                "identifier": f"project:{PROJECT_ID}",
            }
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [(Allow, f"user:{USER_ID}", permissions)]
        for permission in permissions:
            assert jwt_request.has_permission(permission, project)
        project.id = UUID(OTHER_ID)
        for permission in permissions:
            assert not jwt_request.has_permission(permission, project)

    def test_permission_wide_action_does_not_widen_other_details(
        self, jwt_request, claims, sign, project
    ):
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["projects:upload"]},
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{OTHER_ID}",
            },
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [
            (
                Allow,
                f"user:{USER_ID}",
                [Permissions.ProjectsUpload, Permissions.APIObservationsAdd],
            )
        ]
        assert jwt_request.has_permission(Permissions.ProjectsUpload, project)
        assert not jwt_request.has_permission(Permissions.APIObservationsAdd, project)
        project.id = UUID(OTHER_ID)
        assert jwt_request.has_permission(Permissions.ProjectsUpload, project)
        assert jwt_request.has_permission(Permissions.APIObservationsAdd, project)


class TestRegisteredJWTPolicy:
    @pytest.fixture
    def user(self, db_session):
        return UserFactory()

    @pytest.fixture(params=["user", "publisher"])
    def subject_kind(self, request):
        return request.param

    @pytest.fixture
    def subject(self, subject_kind, user):
        return user if subject_kind == "user" else GitHubPublisherFactory()

    @pytest.fixture(autouse=True)
    def upload_claims(self, claims, subject, subject_kind):
        claims.update(
            sub=str(subject.id),
            subject_kind=subject_kind,
            aud=UPLOAD_AUDIENCE,
            authorization_details=[
                {"type": "warehouse", "actions": ["projects:upload"]}
            ],
        )

    @pytest.fixture
    def project(self, subject, subject_kind):
        if subject_kind == "publisher":
            return ProjectFactory(oidc_publishers=[subject])
        project = ProjectFactory()
        RoleFactory(project=project, user=subject, role_name="Owner")
        return project

    def test_rechecks_credential_and_registry_for_each_operation(
        self, make_request, sign, project, registered_jti, mocker
    ):
        token = sign()
        request = make_request("/legacy/?:action=file_upload", token)
        registry = request.find_service(IJWTRegistry, context=None)
        active_check = mocker.spy(registry, "is_active")
        entry_check = mocker.spy(registry, "get_active")
        verifier = request.find_service(IJWTVerifier, context=None)
        verify = mocker.spy(verifier, "verify")

        assert request.identity is not None
        assert request.authentication_method == AuthenticationMethod.API_KEY
        assert request.has_permission(Permissions.ProjectsUpload, project)
        assert not request.has_permission(Permissions.ProjectsUpload, ProjectFactory())
        assert not request.has_permission(Permissions.APIObservationsAdd, project)
        assert not request.has_permission(Permissions.AccountManage, project)
        assert request.has_permission(Permissions.ProjectsUpload, project)
        # Authentication plus four API_KEY permission checks; AccountManage is
        # denied by the method allowlist without needing credential validation.
        entry_check.assert_called_once_with(registered_jti)
        assert active_check.call_args_list == [mocker.call(registered_jti)] * 4
        assert verify.call_args_list == [mocker.call(token)] * 5

    @pytest.mark.parametrize("state", ["missing", "expired", "revoked"])
    def test_inactive_registry_entry_cannot_authenticate(
        self,
        make_request,
        sign,
        claims,
        project,
        jwt_registry,
        registered_jti,
        db_session,
        state,
        mocker,
    ):
        if state == "missing":
            # Another active registry entry cannot authorize this JTI.
            claims["jti"] = OTHER_ID
        elif state == "expired":
            db_session.get(IssuedJWT, registered_jti).expires_at = datetime.now(UTC)
        else:
            jwt_registry.revoke(registered_jti)

        request = make_request("/legacy/?:action=file_upload", sign())
        registry = request.find_service(IJWTRegistry, context=None)
        active_check = mocker.spy(registry, "get_active")
        assert request.identity is None
        assert not request.has_permission(Permissions.ProjectsUpload, project)
        assert not hasattr(request, "authentication_method")
        active_check.assert_called_once_with(UUID(claims["jti"]))

    @pytest.mark.parametrize("authenticated", [False, True])
    def test_database_error_does_not_allow_access(
        self, make_request, sign, project, db_session, mocker, authenticated
    ):
        request = make_request("/legacy/?:action=file_upload", sign())
        if authenticated:
            assert request.identity is not None
        mocker.patch.object(
            db_session,
            "scalar",
            side_effect=OperationalError(
                "statement", {}, Exception("database unavailable")
            ),
        )
        with pytest.raises(OperationalError):
            request.has_permission(Permissions.ProjectsUpload, project)
        assert hasattr(request, "authentication_method") == authenticated

    def test_invalid_signature_does_not_query_registry(
        self, make_request, sign, signing_keys, mocker
    ):
        request = make_request(
            "/legacy/?:action=file_upload", sign(key=signing_keys[1])
        )
        registry = request.find_service(IJWTRegistry, context=None)
        entry_check = mocker.spy(registry, "get_active")
        active_check = mocker.spy(registry, "is_active")
        assert request.identity is None
        entry_check.assert_not_called()
        active_check.assert_not_called()

    @pytest.mark.parametrize("expiration", ["token", "registry"])
    def test_expiration_denies_authorization_with_cached_identity(
        self,
        make_request,
        sign,
        claims,
        project,
        registered_jti,
        db_session,
        clock,
        expiration,
        mocker,
    ):
        expires_at = datetime.fromtimestamp(
            NOW + 1 if expiration == "registry" else claims["exp"], UTC
        )
        if expiration == "registry":
            db_session.get(IssuedJWT, registered_jti).expires_at = expires_at
        token = sign()
        request = make_request("/legacy/?:action=file_upload", token)
        active_check = mocker.spy(
            request.find_service(IJWTRegistry, context=None), "is_active"
        )
        assert request.identity is not None

        clock.move_to(expires_at)
        result = request.has_permission(Permissions.ProjectsUpload, project)
        assert not result
        assert result.reason == "invalid_api_key"
        # Expired JWTs fail verification before consulting the registry again.
        assert active_check.call_args_list == [mocker.call(registered_jti)] * (
            1 if expiration == "registry" else 0
        )

        fresh_request = make_request("/legacy/?:action=file_upload", token)
        assert fresh_request.identity is None
        assert not fresh_request.has_permission(Permissions.ProjectsUpload, project)

    @pytest.mark.parametrize("already_authorized", [False, True])
    def test_committed_revocation_denies_authorization_with_cached_identity(
        self,
        make_request,
        sign,
        claims,
        project,
        app_config,
        mocker,
        already_authorized,
    ):
        # The request's DB transaction remains open while another one revokes.
        with Session(app_config.registry["sqlalchemy.engine"]) as writer:
            issuer = DatabaseJWTRegistry(writer)
            token_id = issuer.register(datetime.fromtimestamp(claims["exp"], UTC))
            writer.commit()
            try:
                claims["jti"] = str(token_id)
                token = sign()
                request = make_request("/legacy/?:action=file_upload", token)
                active_check = mocker.spy(
                    request.find_service(IJWTRegistry, context=None), "is_active"
                )
                assert request.identity is not None
                if already_authorized:
                    assert request.has_permission(Permissions.ProjectsUpload, project)

                issuer.revoke(token_id)
                writer.commit()
                result = request.has_permission(Permissions.ProjectsUpload, project)
                assert not result
                assert result.reason == "invalid_api_key"
                assert active_check.call_args_list == [mocker.call(token_id)] * (
                    2 if already_authorized else 1
                )

                fresh_request = make_request("/legacy/?:action=file_upload", token)
                assert fresh_request.identity is None
                assert not fresh_request.has_permission(
                    Permissions.ProjectsUpload, project
                )
            finally:
                issuer.revoke(token_id)
                writer.commit()


class TestSignedObservationJWTPolicy:
    @pytest.fixture
    def user(self, db_session):
        return UserFactory(is_observer=True)

    @pytest.fixture(autouse=True)
    def observation_claims(self, claims, user):
        claims["sub"] = str(user.id)
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]

    def test_observer_can_report_on_unrelated_projects(self, make_request, sign, user):
        projects = [ProjectFactory(), ProjectFactory()]
        token = sign()
        for project in projects:
            request = make_request(
                f"/danger-api/projects/{project.name}/observations", token
            )
            assert request.matched_route.name == "api.projects.observations"
            assert request.identity == UserContext(user, macaroon=None)
            assert request.authentication_method == AuthenticationMethod.API_KEY
            assert request.has_permission(Permissions.APIObservationsAdd, project)

    @pytest.mark.parametrize("narrowed", [False, True])
    @pytest.mark.parametrize("role_name", [None, "Owner", "Maintainer"])
    def test_nonobserver_cannot_report(
        self, make_request, sign, claims, user, narrowed, role_name
    ):
        user.is_observer = False
        project = ProjectFactory()
        if role_name is not None:
            RoleFactory(user=user, project=project, role_name=role_name)
        if narrowed:
            claims["authorization_details"] = [
                {
                    "type": "warehouse",
                    "actions": ["api:observations:add"],
                    "identifier": f"project:{project.id}",
                }
            ]
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.identity == UserContext(user, macaroon=None)
        assert not request.has_permission(Permissions.APIObservationsAdd, project)

    def test_observer_privilege_removal_takes_effect(
        self, make_request, sign, user, db_session
    ):
        project = ProjectFactory()
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.has_permission(Permissions.APIObservationsAdd, project)
        user.is_observer = False
        db_session.flush()
        db_session.expire(user, ["is_observer"])
        assert not request.has_permission(Permissions.APIObservationsAdd, project)

    def test_resource_narrowing(self, make_request, sign, claims):
        allowed, other = ProjectFactory(), ProjectFactory()
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{allowed.id}",
            }
        ]
        token = sign()
        request = make_request(
            f"/danger-api/projects/{allowed.name}/observations", token
        )
        assert request.has_permission(Permissions.APIObservationsAdd, allowed)
        request = make_request(f"/danger-api/projects/{other.name}/observations", token)
        assert request.identity is not None
        assert not request.has_permission(Permissions.APIObservationsAdd, other)

    @pytest.mark.parametrize("include_broad", [False, True])
    def test_details_are_additive(self, make_request, sign, claims, include_broad):
        first, second, other = ProjectFactory(), ProjectFactory(), ProjectFactory()
        claims["authorization_details"] = [
            {
                "type": "warehouse",
                "actions": ["api:observations:add"],
                "identifier": f"project:{project.id}",
            }
            for project in (first, second)
        ]
        if include_broad:
            claims["authorization_details"].append(
                {"type": "warehouse", "actions": ["api:observations:add"]}
            )
        token = sign()
        for project in (first, second, other):
            request = make_request(
                f"/danger-api/projects/{project.name}/observations", token
            )
            assert bool(
                request.has_permission(Permissions.APIObservationsAdd, project)
            ) == (include_broad or project in (first, second))

    def test_grant_does_not_allow_other_operations(self, make_request, sign):
        project = ProjectFactory()
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.has_permission(Permissions.APIObservationsAdd, project)
        assert not request.has_permission(Permissions.APIEcho, project)
        assert not request.has_permission(Permissions.ProjectsUpload, project)

    def test_observer_privilege_does_not_replace_grant(
        self, make_request, sign, claims
    ):
        project = ProjectFactory()
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:echo"]}
        ]
        request = make_request(
            f"/danger-api/projects/{project.name}/observations", sign()
        )
        assert request.identity is not None
        assert not request.has_permission(Permissions.APIObservationsAdd, project)


class TestSignedPublisherJWTPolicy:
    @pytest.fixture(params=[True, False])
    def narrowed_upload(self, request):
        return request.param

    @pytest.fixture
    def expected_audience(self):
        return UPLOAD_AUDIENCE

    @pytest.fixture
    def publisher(self, db_session):
        return GitHubPublisherFactory()

    @pytest.fixture
    def publisher_project(self, publisher):
        return ProjectFactory(oidc_publishers=[publisher])

    @pytest.fixture
    def jwt_request(
        self,
        verifier,
        publisher,
        publisher_project,
        claims,
        sign,
        db_session,
        mocker,
        expected_audience,
        narrowed_upload,
        jwt_registry,
        registered_jti,
    ):
        upload_detail = {"type": "warehouse", "actions": ["projects:upload"]}
        if narrowed_upload:
            upload_detail["identifier"] = f"project:{publisher_project.id}"
        claims.update(
            sub=str(publisher.id),
            subject_kind="publisher",
            aud=expected_audience,
            authorization_details=[
                upload_detail,
                {"type": "warehouse", "actions": ["api:echo"]},
            ],
        )
        user_service = mocker.Mock(spec=["get_user", "is_disabled"])
        with testing.testConfig() as config:
            config.include("pyramid_services")
            config.register_service(verifier, IJWTVerifier)
            config.register_service(jwt_registry, IJWTRegistry)
            config.register_service(user_service, IUserService)
            config.set_security_policy(MultiSecurityPolicy([JWTSecurityPolicy()]))
            config.commit()
            request = Request.blank("/")
            request.registry = config.registry
            apply_request_extensions(request)
            request.db = db_session
            request.matched_route = types.SimpleNamespace(
                predicates=[AuthMethodsPredicate({"api-key"}, None)]
            )
            request.headers["Authorization"] = f"Bearer {sign()}"
            yield request
        user_service.get_user.assert_not_called()
        user_service.is_disabled.assert_not_called()

    def test_publisher_uses_existing_identity_contract(
        self, jwt_request, publisher, publisher_project
    ):
        assert jwt_request.identity == PublisherTokenContext(publisher, claims=None)
        assert jwt_request.authenticated_userid is None
        assert _user(jwt_request) is None
        assert _oidc_publisher(jwt_request) is publisher
        assert _oidc_claims(jwt_request) is None
        assert jwt_request.authentication_method == AuthenticationMethod.API_KEY
        assert jwt_request.has_permission(Permissions.ProjectsUpload, publisher_project)

    def test_removing_publisher_from_project_denies(
        self, jwt_request, publisher_project, db_session
    ):
        assert jwt_request.has_permission(Permissions.ProjectsUpload, publisher_project)
        publisher_project.oidc_publishers.clear()
        db_session.flush()
        db_session.expire(publisher_project, ["oidc_publishers"])
        assert not jwt_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

    def test_new_project_membership_respects_scope(
        self, jwt_request, publisher, narrowed_upload, db_session
    ):
        # Reuse the exact signed token and cached identity after membership changes.
        assert jwt_request.identity is not None
        original_header = jwt_request.headers["Authorization"]
        other = ProjectFactory()
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, other)
        other.oidc_publishers.append(publisher)
        db_session.flush()
        db_session.expire(other, ["oidc_publishers"])
        assert bool(jwt_request.has_permission(Permissions.ProjectsUpload, other)) == (
            not narrowed_upload
        )
        assert jwt_request.headers["Authorization"] == original_header

    def test_unrelated_project_denies(self, jwt_request):
        other = ProjectFactory(oidc_publishers=[GitHubPublisherFactory()])
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, other)

    def test_project_context_required_even_with_granting_acl(
        self, jwt_request, publisher, publisher_project
    ):
        context = types.SimpleNamespace(
            id=publisher_project.id,
            __acl__=[(Allow, f"oidc:{publisher.id}", Permissions.ProjectsUpload)],
        )
        assert not jwt_request.has_permission(Permissions.ProjectsUpload, context)

    def test_upload_grant_does_not_allow_other_permissions(
        self, jwt_request, publisher, claims, sign, project
    ):
        claims["authorization_details"] = [claims["authorization_details"][0]]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        project.__acl__ = [
            (
                Allow,
                f"oidc:{publisher.id}",
                [Permissions.APIEcho, Permissions.APIObservationsAdd],
            )
        ]
        assert not jwt_request.has_permission(Permissions.APIEcho, project)
        assert not jwt_request.has_permission(Permissions.APIObservationsAdd, project)

    def test_wrong_audience_denies(self, jwt_request, claims, sign):
        claims["aud"] = API_AUDIENCE
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert jwt_request.identity is None

    def test_deleting_publisher_denies(self, jwt_request, publisher, db_session):
        db_session.delete(publisher)
        db_session.flush()
        assert jwt_request.identity is None

    @pytest.mark.parametrize(
        "status", [LifecycleStatus.Archived, LifecycleStatus.QuarantineEnter]
    )
    def test_project_status_still_applies(self, jwt_request, publisher_project, status):
        publisher_project.lifecycle_status = status
        assert not jwt_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )

    def test_rechecks_expiration(self, jwt_request, publisher_project, clock, claims):
        assert jwt_request.identity is not None
        clock.move_to(datetime.fromtimestamp(claims["exp"], UTC))
        result = jwt_request.has_permission(
            Permissions.ProjectsUpload, publisher_project
        )
        assert not result
        assert result.reason == "invalid_api_key"

    @pytest.mark.parametrize("expected_audience", [API_AUDIENCE])
    def test_publisher_subject_is_not_upload_specific(self, jwt_request, publisher):
        # This is an explicitly granting test ACL, not a change to the danger API.
        context = types.SimpleNamespace(
            __acl__=[(Allow, f"oidc:{publisher.id}", Permissions.APIEcho)]
        )
        assert jwt_request.has_permission(Permissions.APIEcho, context)

    @pytest.mark.parametrize("scheme", ["Basic", "Token"])
    def test_signed_publisher_jwt_is_bearer_only(self, jwt_request, sign, scheme):
        token = sign()
        if scheme == "Basic":
            token = base64.b64encode(f"__token__:{token}".encode()).decode()
        jwt_request.headers["Authorization"] = f"{scheme} {token}"
        assert jwt_request.identity is None

    @pytest.mark.parametrize("expected_audience", [API_AUDIENCE])
    def test_publisher_cannot_report_observations_even_with_permission_wide_grant(
        self, jwt_request, claims, sign, publisher_project
    ):
        claims["authorization_details"] = [
            {"type": "warehouse", "actions": ["api:observations:add"]}
        ]
        jwt_request.headers["Authorization"] = f"Bearer {sign()}"
        assert isinstance(jwt_request.identity, PublisherTokenContext)
        assert not jwt_request.has_permission(
            Permissions.APIObservationsAdd, publisher_project
        )
