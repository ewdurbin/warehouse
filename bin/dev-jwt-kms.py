#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Create an emulated KMS key and print a local Compose override as JSON."""

import argparse
import json
import sys

from pathlib import Path

import boto3

from cryptography.hazmat.primitives import serialization

REGION = "us-east-1"
ENDPOINT = "http://kms:8080"
LOCAL_CREDENTIAL = "local-development-only"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rotate-from",
        type=Path,
        help="Retain verification keys from a previous generated Compose override",
    )
    args = parser.parse_args()
    verification_keys = {}
    if args.rotate_from:
        previous = json.loads(args.rotate_from.read_text())
        verification_keys = json.loads(
            previous["services"]["web"]["environment"]["JWT_VERIFICATION_KEYS"]
        )

    client = boto3.client(
        "kms",
        region_name=REGION,
        endpoint_url=ENDPOINT,
        aws_access_key_id=LOCAL_CREDENTIAL,
        aws_secret_access_key=LOCAL_CREDENTIAL,
    )
    key_id = client.create_key(KeyUsage="SIGN_VERIFY", KeySpec="RSA_2048")[
        "KeyMetadata"
    ]["KeyId"]
    public_key = serialization.load_der_public_key(
        client.get_public_key(KeyId=key_id)["PublicKey"]
    )
    kid = f"local-{key_id}"
    verification_keys[kid] = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    environment = {
        "AWS_ACCESS_KEY_ID": LOCAL_CREDENTIAL,
        "AWS_SECRET_ACCESS_KEY": LOCAL_CREDENTIAL,
        "AWS_REGION": REGION,
        "AWS_ENDPOINT_URL_KMS": ENDPOINT,
        "JWT_ENABLED": "true",
        "JWT_ISSUER": "urn:warehouse:local",
        "JWT_UPLOAD_AUDIENCE": "urn:warehouse:local:upload",
        "JWT_API_AUDIENCE": "urn:warehouse:local:api",
        "JWT_SIGNING_KEY_ID": kid,
        "JWT_KMS_KEY_ID": key_id,
        "JWT_VERIFICATION_KEYS": json.dumps(verification_keys),
    }
    json.dump(
        {
            "services": {
                "web": {
                    "environment": environment,
                    "depends_on": {"kms": {"condition": "service_started"}},
                }
            }
        },
        sys.stdout,
        indent=2,
    )
    print()


if __name__ == "__main__":
    main()
