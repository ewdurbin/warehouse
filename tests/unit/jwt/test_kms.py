# SPDX-License-Identifier: Apache-2.0

from copy import copy, deepcopy
from hashlib import sha256

import jwt
import pytest

from botocore.exceptions import ClientError
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyramid.exceptions import ConfigurationError
from sqlalchemy import func, select

from warehouse.jwt.issuer import WarehouseJWTIssuer
from warehouse.jwt.kms import SIGNING_ALGORITHM
from warehouse.jwt.models import IssuedJWT
from warehouse.jwt.services import jwt_issuer_factory, jwt_verifier_factory

KMS_ALIAS = "alias/pypi-access"
CURRENT_KEY_ARN = (
    "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc"
)
NEXT_KEY_ARN = (
    "arn:aws:kms:us-east-1:111122223333:key/87654321-4321-4321-4321-cba987654321"
)


def public_key_bytes(key, encoding):
    return key.public_key().public_bytes(
        encoding, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture
def kms(warehouse_jwt_key, mocker):
    keys = {CURRENT_KEY_ARN: warehouse_jwt_key}
    aliases = {KMS_ALIAS: CURRENT_KEY_ARN}
    client = mocker.Mock(spec=["get_public_key", "sign"])

    def get_public_key(**request):
        key_id = request["KeyId"]
        arn = aliases.get(key_id, key_id)
        return {
            "KeyId": arn,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [SIGNING_ALGORITHM],
            "PublicKey": public_key_bytes(keys[arn], serialization.Encoding.DER),
        }

    def sign(**request):
        return {
            "Signature": keys[request["KeyId"]].sign(
                request["Message"],
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        }

    client.get_public_key.side_effect = get_public_key
    client.sign.side_effect = sign
    session = mocker.patch("warehouse.jwt.kms.boto3.session.Session")
    session.return_value.client.return_value = client
    return client, keys, aliases


@pytest.fixture
def kms_settings(warehouse_jwt_settings):
    del warehouse_jwt_settings["warehouse.jwt.signing_key"]
    warehouse_jwt_settings["warehouse.jwt.kms_key_id"] = KMS_ALIAS
    return warehouse_jwt_settings


def test_signing_and_rotation(
    kms, kms_settings, signing_keys, jwt_registry, issue_args, clock
):
    client, keys, aliases = kms
    old_factory = jwt_issuer_factory(kms_settings)

    # Repointing the alias must not silently change the signing key of an
    # already-configured process.
    keys[NEXT_KEY_ARN] = signing_keys[0]
    aliases[KMS_ALIAS] = NEXT_KEY_ARN
    old = WarehouseJWTIssuer(registry=jwt_registry, config=old_factory).issue(
        **issue_args
    )
    client.sign.assert_called_once_with(
        KeyId=CURRENT_KEY_ARN,
        Message=sha256(old.token.rsplit(".", 1)[0].encode("ascii")).digest(),
        MessageType="DIGEST",
        SigningAlgorithm=SIGNING_ALGORITHM,
    )

    kms_settings["warehouse.jwt.signing_key_id"] = "next"
    kms_settings["warehouse.jwt.verification_keys"]["next"] = public_key_bytes(
        keys[NEXT_KEY_ARN], serialization.Encoding.PEM
    ).decode("ascii")
    new_factory = jwt_issuer_factory(kms_settings)
    new = WarehouseJWTIssuer(registry=jwt_registry, config=new_factory).issue(
        **issue_args
    )
    verifier = jwt_verifier_factory(kms_settings).for_audience("upload")(None, None)
    assert jwt.get_unverified_header(old.token)["kid"] == "current"
    assert jwt.get_unverified_header(new.token)["kid"] == "next"
    assert verifier.verify(old.token).jti == old.jti
    assert verifier.verify(new.token).jti == new.jti
    assert client.sign.call_args.kwargs["KeyId"] == NEXT_KEY_ARN
    assert client.get_public_key.call_count == 2

    del kms_settings["warehouse.jwt.verification_keys"]["current"]
    retired = jwt_verifier_factory(kms_settings).for_audience("upload")(None, None)
    assert retired.verify(old.token) is None
    assert retired.verify(new.token).jti == new.jti


def test_rejects_mismatched_public_key(kms, kms_settings, signing_keys):
    client, keys, _ = kms
    keys[CURRENT_KEY_ARN] = signing_keys[0]
    with pytest.raises(ConfigurationError, match="JWT signing configuration"):
        jwt_issuer_factory(kms_settings)
    client.sign.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("KeyId", KMS_ALIAS),
        ("KeyUsage", "ENCRYPT_DECRYPT"),
        ("SigningAlgorithms", ["RSASSA_PSS_SHA_256"]),
    ],
)
def test_rejects_incompatible_key(kms, kms_settings, field, value):
    client, _, _ = kms
    response = client.get_public_key(KeyId=KMS_ALIAS)
    response[field] = value
    client.get_public_key.side_effect = None
    client.get_public_key.return_value = response
    with pytest.raises(ConfigurationError, match="JWT signing configuration"):
        jwt_issuer_factory(kms_settings)
    client.sign.assert_not_called()


def test_rejects_two_signing_backends(warehouse_jwt_settings):
    warehouse_jwt_settings["warehouse.jwt.kms_key_id"] = KMS_ALIAS
    with pytest.raises(ConfigurationError, match="exactly one signing key"):
        jwt_issuer_factory(warehouse_jwt_settings)


def test_key_is_signing_only(kms, kms_settings):
    key = jwt_issuer_factory(kms_settings).key
    assert copy(key) is key
    assert deepcopy(key) is key
    with pytest.raises(UnsupportedAlgorithm, match="RS256"):
        key.sign(b"data", padding.PKCS1v15(), hashes.SHA384())
    with pytest.raises(UnsupportedAlgorithm, match="RS256"):
        key.decrypt(b"data", padding.PKCS1v15())
    with pytest.raises(UnsupportedAlgorithm, match="cannot be exported"):
        key.private_numbers()
    with pytest.raises(UnsupportedAlgorithm, match="cannot be exported"):
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def test_sign_failure_rolls_back(
    kms, kms_settings, jwt_registry, issue_args, db_session
):
    client, _, _ = kms
    issuer = WarehouseJWTIssuer(
        registry=jwt_registry, config=jwt_issuer_factory(kms_settings)
    )
    client.sign.side_effect = ClientError(
        {"Error": {"Code": "KMSInternalException", "Message": "unavailable"}},
        "Sign",
    )
    with pytest.raises(ClientError), db_session.begin_nested():
        issuer.issue(**issue_args)
    assert db_session.scalar(select(func.count()).select_from(IssuedJWT)) == 0
