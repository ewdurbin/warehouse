# SPDX-License-Identifier: Apache-2.0

import json
import os

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

import boto3.session
import jwt

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)
from jwt.algorithms import RSAAlgorithm
from pyramid.exceptions import ConfigurationError
from zope.interface import implementer

from warehouse.jwt.interfaces import IJWTSigner
from warehouse.jwt.profile import MEDIA_TYPE

KMS_SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"


class _KMSRS256Algorithm(RSAAlgorithm):
    """Use KMS for the signing step of an instance-local PyJWT JWS encoder."""

    def __init__(self, client, key_arn):
        super().__init__(RSAAlgorithm.SHA256)
        self._client = client
        self._key_arn = key_arn

    def sign(self, msg, key):
        return self._client.sign(
            KeyId=self._key_arn,
            Message=sha256(msg).digest(),
            MessageType="DIGEST",
            SigningAlgorithm=KMS_SIGNING_ALGORITHM,
        )["Signature"]


@implementer(IJWTSigner)
@dataclass(frozen=True, repr=False)
class _JWTSignerService:
    _key_id: str
    _key: RSAPrivateKey | RSAPublicKey
    _jws: jwt.PyJWS

    def sign(self, claims: dict[str, object]) -> str:
        payload = json.dumps(claims, separators=(",", ":"), allow_nan=False).encode()
        return self._jws.encode(
            payload,
            self._key,
            algorithm="RS256",
            headers={"typ": MEDIA_TYPE, "kid": self._key_id},
        )


class KMSJWTSignerService(_JWTSignerService):
    """Sign with a KMS key pinned to its immutable ARN at application startup."""

    @classmethod
    def from_settings(cls, settings):
        key_id = settings.get("warehouse.jwt.signing_key_id")
        kms_key_id = settings.get("warehouse.jwt.kms_key_id")
        verification_keys = settings.get("warehouse.jwt.verification_keys")
        if (
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(kms_key_id, str)
            or not kms_key_id
            or not isinstance(verification_keys, Mapping)
            or not isinstance(verification_keys.get(key_id), str)
        ):
            raise ConfigurationError(
                "JWT signing requires a KMS key and a key ID in verification_keys"
            )

        try:
            expected_public_key = load_pem_public_key(
                verification_keys[key_id].encode("utf-8")
            )
            client = boto3.session.Session(
                region_name=settings.get("aws.region")
            ).client(
                "kms",
                config=Config(
                    connect_timeout=2,
                    read_timeout=2,
                    retries={"mode": "standard", "total_max_attempts": 2},
                ),
            )
            response = client.get_public_key(KeyId=kms_key_id)
            key_arn = response["KeyId"]
            public_key = load_der_public_key(response["PublicKey"])
            if (
                not isinstance(key_arn, str)
                or not key_arn.startswith("arn:")
                or ":key/" not in key_arn
                or response.get("KeyUsage") != "SIGN_VERIFY"
                or KMS_SIGNING_ALGORITHM not in response.get("SigningAlgorithms", ())
                or not isinstance(public_key, RSAPublicKey)
                or public_key.key_size < 2048
                or public_key != expected_public_key
            ):
                raise ValueError("KMS key does not match the JWT signing configuration")
        except (
            BotoCoreError,
            ClientError,
            KeyError,
            TypeError,
            ValueError,
            UnsupportedAlgorithm,
        ) as exc:
            raise ConfigurationError("Invalid JWT signing configuration") from exc

        jws = jwt.PyJWS(algorithms=[])
        jws.register_algorithm("RS256", _KMSRS256Algorithm(client, key_arn))
        return cls(key_id, public_key, jws)


class TestJWTSignerService(_JWTSignerService):
    """An in-memory signer for tests; never selectable through app configuration."""

    def __init__(self, *, key_id: str, key: RSAPrivateKey):
        if "PYTEST_CURRENT_TEST" not in os.environ:
            raise RuntimeError("TestJWTSignerService is only available during tests")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("A JWT signing key ID is required")
        if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("JWT signing requires RSA private keys >= 2048 bits")
        super().__init__(key_id, key, jwt.PyJWS(algorithms=["RS256"]))
