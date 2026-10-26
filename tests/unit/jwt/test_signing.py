# SPDX-License-Identifier: Apache-2.0

from hashlib import sha256

import boto3.session
import jwt
import pytest

from botocore.exceptions import ClientError
from botocore.stub import Stubber
from cryptography.hazmat.primitives import serialization
from jwt.utils import base64url_decode
from pyramid.exceptions import ConfigurationError
from zope.interface.verify import verifyClass

from tests.common.jwt import API_AUDIENCE, ISSUER
from warehouse.jwt.interfaces import IJWTSigner
from warehouse.jwt.signing import (
    KMS_SIGNING_ALGORITHM,
    KMSJWTSignerService,
    TestJWTSignerService as JWTTestSigner,
)
from warehouse.jwt.verifier import WarehouseJWTVerifier

KMS_ALIAS = "alias/pypi-access"
CURRENT_ARN = (
    "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc"
)
NEXT_ARN = "arn:aws:kms:us-east-1:111122223333:key/87654321-4321-4321-4321-cba987654321"


def public_key_response(arn, key):
    return {
        "KeyId": arn,
        "KeyUsage": "SIGN_VERIFY",
        "SigningAlgorithms": [KMS_SIGNING_ALGORITHM],
        "PublicKey": key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    }


def sign_request(token, arn):
    return {
        "KeyId": arn,
        "Message": sha256(token.rsplit(".", 1)[0].encode("ascii")).digest(),
        "MessageType": "DIGEST",
        "SigningAlgorithm": KMS_SIGNING_ALGORITHM,
    }


def stub_signature(stubber, token, arn):
    signature = base64url_decode(token.rsplit(".", 1)[1].encode("ascii"))
    stubber.add_response("sign", {"Signature": signature}, sign_request(token, arn))


@pytest.fixture
def kms_stubber(mocker):
    session = boto3.session.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-east-1",
    )
    client = session.client("kms")
    mocker.patch.object(boto3.session.Session, "client", return_value=client)
    with Stubber(client) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


@pytest.fixture
def signing_settings(jwt_settings):
    return jwt_settings | {
        "warehouse.jwt.signing_key_id": "current",
        "warehouse.jwt.kms_key_id": KMS_ALIAS,
    }


@pytest.mark.parametrize("service", [KMSJWTSignerService, JWTTestSigner])
def test_signer_interface(service):
    assert verifyClass(IJWTSigner, service)


def test_test_signer_cannot_run_outside_tests(signing_keys, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(RuntimeError, match="only available during tests"):
        JWTTestSigner(key_id="current", key=signing_keys[0])


def test_kms_signing_and_rotation(
    kms_stubber, signing_settings, signing_keys, claims, clock
):
    current_key, next_key = signing_keys
    next_settings = signing_settings | {
        "warehouse.jwt.signing_key_id": "next",
        "warehouse.jwt.verification_keys": {
            **signing_settings["warehouse.jwt.verification_keys"],
            "next": signing_settings["warehouse.jwt.verification_keys"]["previous"],
        },
    }
    current_token = JWTTestSigner(key_id="current", key=current_key).sign(claims)
    next_token = JWTTestSigner(key_id="next", key=next_key).sign(claims)
    kms_stubber.add_response(
        "get_public_key",
        public_key_response(CURRENT_ARN, current_key),
        {"KeyId": KMS_ALIAS},
    )
    kms_stubber.add_response(
        "get_public_key", public_key_response(NEXT_ARN, next_key), {"KeyId": KMS_ALIAS}
    )
    stub_signature(kms_stubber, current_token, CURRENT_ARN)
    stub_signature(kms_stubber, next_token, NEXT_ARN)

    current_signer = KMSJWTSignerService.from_settings(signing_settings)
    next_signer = KMSJWTSignerService.from_settings(next_settings)
    current = current_signer.sign(claims)
    next_ = next_signer.sign(claims)
    verifier = WarehouseJWTVerifier(
        issuer=ISSUER,
        audience=API_AUDIENCE,
        keys={"current": current_key.public_key(), "next": next_key.public_key()},
    )
    assert jwt.get_unverified_header(current)["kid"] == "current"
    assert jwt.get_unverified_header(next_)["kid"] == "next"
    assert verifier.verify(current) is not None
    assert verifier.verify(next_) is not None


@pytest.mark.parametrize(
    "setting", ["signing_key_id", "kms_key_id", "verification_keys"]
)
def test_incomplete_signing_configuration(signing_settings, setting):
    del signing_settings[f"warehouse.jwt.{setting}"]
    with pytest.raises(ConfigurationError, match="KMS key and a key ID"):
        KMSJWTSignerService.from_settings(signing_settings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("KeyId", KMS_ALIAS),
        ("KeyUsage", "ENCRYPT_DECRYPT"),
        ("SigningAlgorithms", ["RSASSA_PSS_SHA_256"]),
    ],
)
def test_rejects_incompatible_kms_key(
    kms_stubber, signing_settings, signing_keys, field, value
):
    response = public_key_response(CURRENT_ARN, signing_keys[0]) | {field: value}
    kms_stubber.add_response("get_public_key", response, {"KeyId": KMS_ALIAS})
    with pytest.raises(ConfigurationError, match="JWT signing configuration"):
        KMSJWTSignerService.from_settings(signing_settings)


def test_rejects_mismatched_public_key(kms_stubber, signing_settings, signing_keys):
    kms_stubber.add_response(
        "get_public_key",
        public_key_response(CURRENT_ARN, signing_keys[1]),
        {"KeyId": KMS_ALIAS},
    )
    with pytest.raises(ConfigurationError, match="JWT signing configuration"):
        KMSJWTSignerService.from_settings(signing_settings)


def test_kms_signing_error_propagates(
    kms_stubber, signing_settings, signing_keys, claims
):
    key = signing_keys[0]
    token = JWTTestSigner(key_id="current", key=key).sign(claims)
    kms_stubber.add_response(
        "get_public_key", public_key_response(CURRENT_ARN, key), {"KeyId": KMS_ALIAS}
    )
    kms_stubber.add_client_error(
        "sign",
        service_error_code="KMSInternalException",
        expected_params=sign_request(token, CURRENT_ARN),
    )
    signer = KMSJWTSignerService.from_settings(signing_settings)
    with pytest.raises(ClientError, match="KMSInternalException"):
        signer.sign(claims)
