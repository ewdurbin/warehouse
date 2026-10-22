# SPDX-License-Identifier: Apache-2.0

import hmac
import json
import types

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
from zope.interface.verify import verifyClass

from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.interfaces import IJWTVerifier
from warehouse.jwt.security_policy import JWTSecurityPolicy
from warehouse.jwt.services import DisabledJWTVerifier, jwt_verifier_factory
from warehouse.jwt.verifier import WarehouseJWTVerifier, WarehouseJWTVerifierFactory
from warehouse.packaging.models import Project
from warehouse.predicates import AuthMethodsPredicate, JWTAudiencePredicate
from warehouse.routes import includeme as include_routes
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
        assert verifier.verify(sign()) == USER_ID
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


class TestAudienceJWTService:
    @pytest.fixture
    def jwt_enabled(self):
        return True

    @pytest.fixture
    def make_request(self, jwt_settings, jwt_enabled, user, mocker, clock):
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
                request.headers["Authorization"] = f"Bearer {token}"
                match = mapper(request)
                request.matched_route = match["route"]
                request.matchdict = match["match"]
                return request

            yield make_request

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
        mocker.patch("warehouse.jwt.verifier.jwt.decode", side_effect=error)
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
