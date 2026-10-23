# Trusted Publisher JWT trial

Trusted Publishers can opt in to a five-minute upload JWT by sending
`"token_format": "jwt"` to the OIDC exchange. The default is a 15-minute macaroon.

## Run the integration tests

With the [Compose development setup](getting-started.md) built, run:

```shell
make tests T=tests/functional/forklift/test_jwt.py
```

These tests use a temporary database on Compose's PostgreSQL service and
separate RSA keys for upstream assertions and Warehouse JWTs. They replace
provider key discovery and the replay cache with local test doubles. The
attestation tests check provenance handling. Signature verification for
attestations is outside their scope.

The tests cover exchange, uploads, changes to publisher associations,
self-revocation, replay protection for assertions with a `jti`, and the default
macaroon flow. Run the verifier and route-policy tests to check expiry and
audience enforcement.

```shell
make tests T="tests/unit/jwt/test_verifier.py tests/unit/jwt/test_route_policy.py"
```

## Start the local server

Set a dedicated upstream audience for the local trial in
`docker-compose.override.yaml`.

```yaml
services:
  web:
    environment:
      OIDC_AUDIENCE: pypi-jwt-local
```

Run `make runmigrations` to create the issued-token registry. Then start
Traefik and its dependencies, including the web service:

```shell
docker compose up -d traefik
```

Compose loads two development signing keys. Warehouse signs with `local-1`
and trusts both public keys. See [local JWT signing](getting-started.md#local-jwt-signing)
to try rotating to `local-2`.

!!! warning "Use the development OIDC backend only locally"

    `dev/environment` selects `NullOIDCPublisherService`, which skips upstream
    signature verification and replay protection. The development debug
    toolbar exposes application settings.

    For shared trials, use a non-development configuration with
    `OIDC_BACKEND=warehouse.oidc.services.OIDCPublisherService` and the usual
    publisher registration, provider configuration, and feature flags.

### Get a local trial assertion

For example, add a disposable service account as a
[Google Cloud Trusted Publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
on your local project. Use `sampleproject` for the client example below.

From a `gcloud` session authorized to impersonate the service account, replace
`SERVICE_ACCOUNT_EMAIL` with its email address and request a fresh assertion
for the local audience.

```shell
OIDC_TOKEN="$(gcloud auth print-identity-token \
  --impersonate-service-account=SERVICE_ACCOUNT_EMAIL \
  --audiences=pypi-jwt-local \
  --include-email)"
export OIDC_TOKEN
```

## Exchange, upload, and revoke

Register a Trusted Publisher or a pending publisher. Request a fresh provider
assertion for the audience returned by `GET /_/oidc/audience` (`OIDC_AUDIENCE`).
Warehouse uses `JWT_UPLOAD_AUDIENCE` for the upload token it issues.

1. POST `/_/oidc/mint-token` with
   `{"token": "<upstream OIDC assertion>", "token_format": "jwt"}`.
   The response contains `success`, `token`, and `expires` (Unix seconds).
   Warehouse selects the publisher, upload audience, permission, and lifetime.
2. Upload with `Authorization: Bearer <token>` using the returned Warehouse
   JWT. Keep using the existing Basic `__token__` flow for macaroon clients
   that rely on it.
3. POST `/_/oidc/burn-token` with `{"token": "<Warehouse JWT>"}` to revoke the
   JWT, including during cleanup after a failed upload. The body alone carries
   the credential. HTTP 202 covers a successful burn as well as invalid,
   expired, or already-burned tokens. Treat a server error as a failed burn.

A valid JWT can upload to any project currently linked to its publisher,
subject to the project's ACL. Adding or removing a link changes which projects
the same token can upload to. A burn deletes the token's registry entry, so
later permission checks fail. Uploads that already passed authorization can
continue.

With the real OIDC backend, Warehouse rejects reuse of an assertion with a
`jti`. Replay protection depends on that claim being present. If KMS signing
fails, request a fresh assertion before retrying, since Warehouse may already
have recorded the previous `jti`.

If JWT issuance is disabled, exchange returns HTTP 422 (`not-enabled`) before
consuming the assertion. Older servers may ignore `token_format` and return a
macaroon. Check the returned format before trying a Bearer JWT upload.

### Local client example

This script uses `requests` and uploads the checkout's `sampleproject` fixture.
Run it from the checkout root with a publisher configured for `sampleproject`
and a version/artifact combination you can upload. Set `WAREHOUSE_URL` if your
server uses a custom host or port. Supply the matching provider assertion in
`OIDC_TOKEN`. The script sends it only to the exchange. Use HTTPS and the
deployment's exchange and upload hosts when adapting the example for remote use.

```python
import hashlib
import os
from pathlib import Path

import requests

base = os.environ.get("WAREHOUSE_URL", "http://localhost").rstrip("/")
artifact = Path("tests/functional/_fixtures/sampleproject-3.0.0.tar.gz")
content = artifact.read_bytes()

with requests.Session() as client:
    client.trust_env = False  # Skip .netrc credentials and environment proxies.
    response = client.post(
        f"{base}/_/oidc/mint-token",
        json={"token": os.environ["OIDC_TOKEN"], "token_format": "jwt"},
        timeout=30,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Exchange failed: HTTP {response.status_code}")
    credential = response.json()["token"]
    if credential.startswith("pypi-") or credential.count(".") != 2:
        raise RuntimeError("The server did not return a JWT; no fallback attempted")
    # Warehouse verifies the signature when the client uploads.
    try:
        response = client.post(
            f"{base}/legacy/",
            headers={"Authorization": f"Bearer {credential}"},
            data={
                ":action": "file_upload",
                "name": "sampleproject",
                "version": "3.0.0",
                "metadata_version": "2.1",
                "filetype": "sdist",
                "sha256_digest": hashlib.sha256(content).hexdigest(),
            },
            files={"content": (artifact.name, content)},
            timeout=60,
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Upload failed: HTTP {response.status_code}")
    finally:
        response = client.post(
            f"{base}/_/oidc/burn-token",
            json={"token": credential},
            timeout=30,
            allow_redirects=False,
        )
        if response.status_code != 202:
            raise RuntimeError(f"Revocation failed: HTTP {response.status_code}")
```

## Rollout and rollback

Apply the registry migration. Ensure Celery Beat schedules the hourly cleanup
and a Celery worker processes it. Set the issuer, audiences, and public keys on
every verifier. Configure the two signing IDs and grant KMS access on issuing
workloads. Use the real OIDC backend and HTTPS for shared deployments, and
confirm that participating clients support Bearer uploads.

See [JWT signing and rotation](../security/security-policy-flow.md#jwt-signing-and-rotation)
for the production key rotation procedure.

To stop issuing JWTs, remove `JWT_SIGNING_KEY_ID` and `JWT_KMS_KEY_ID` and
reload the issuers. Keep the public keys in place while clients use or burn
existing tokens. Once those tokens have expired or been revoked, unset
`JWT_VERIFICATION_KEYS` and reload the verifiers.

To stop the local trial, run `docker compose stop traefik web kms`.

See the [JWT profile](../security/security-policy-flow.md#jwt-profile) for the
token format, authorization rules, and settings.
