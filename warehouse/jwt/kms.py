# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

import boto3.session

from botocore.config import Config
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_der_public_key

SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"


@dataclass(frozen=True, repr=False)
class KMSRSAPrivateKey(rsa.RSAPrivateKey):
    """A signing-only RSA private key handle for PyJWT.

    The private key stays in KMS. Its immutable key ARN and public key are
    resolved once at startup, so changing a KMS alias cannot change which key
    signs JWTs under an already configured ``kid``.
    """

    _client: Any
    _key_arn: str
    _public_key: rsa.RSAPublicKey

    @classmethod
    def load(cls, key_id: str, *, region_name: str | None):
        client = boto3.session.Session(region_name=region_name).client(
            "kms",
            config=Config(
                connect_timeout=2,
                read_timeout=2,
                retries={"mode": "standard", "total_max_attempts": 2},
            ),
        )
        response = client.get_public_key(KeyId=key_id)
        key_arn = response.get("KeyId")
        if (
            not isinstance(key_arn, str)
            or not key_arn.startswith("arn:")
            or ":key/" not in key_arn
            or response.get("KeyUsage") != "SIGN_VERIFY"
            or SIGNING_ALGORITHM not in response.get("SigningAlgorithms", ())
        ):
            raise ValueError("KMS key must support RS256 signing")
        public_key = load_der_public_key(response["PublicKey"])
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("KMS signing key must be RSA")
        return cls(client, key_arn, public_key)

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    def public_key(self) -> rsa.RSAPublicKey:
        return self._public_key

    def sign(self, data: bytes, padding, algorithm) -> bytes:
        if not isinstance(padding, PKCS1v15) or not isinstance(
            algorithm, hashes.SHA256
        ):
            raise UnsupportedAlgorithm("KMS key only supports RS256 signing")
        return self._client.sign(
            KeyId=self._key_arn,
            Message=sha256(data).digest(),
            MessageType="DIGEST",
            SigningAlgorithm=SIGNING_ALGORITHM,
        )["Signature"]

    def decrypt(self, ciphertext, padding):
        raise UnsupportedAlgorithm("KMS key only supports RS256 signing")

    def private_numbers(self):
        raise UnsupportedAlgorithm("KMS private keys cannot be exported")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise UnsupportedAlgorithm("KMS private keys cannot be exported")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self
