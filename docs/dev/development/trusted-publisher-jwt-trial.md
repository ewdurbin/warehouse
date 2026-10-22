# Trusted Publisher JWT trial

This guide covers the opt-in Trusted Publisher JWT trial. Verification and
issuance are **disabled by default**. The exchange continues to issue macaroons
unless a client requests `"token_format": "jwt"`. Trial JWTs authorize
publisher-backed uploads.

## Run the local integration tests

With the [Compose development setup](getting-started.md) built, run:

```shell
make tests T=tests/functional/forklift/test_jwt.py
```

Tests use a temporary database on Compose's PostgreSQL service and verify
signatures with separate RSA keys for upstream assertions and Warehouse JWTs.
They use local test doubles for provider key discovery and the replay cache.
Attestation tests exercise provenance without verifying attestation signatures.

The tests cover exchange, upload, publisher changes, self-revocation, expiry,
audience separation, replay protection for assertions with a `jti`, and the
existing macaroon flow.

## Enable a local web-server trial

Apply the registry migration with `make runmigrations` before issuing tokens.
The registry and its `additional` metadata column must exist on every deployment
using the feature.

Start the opt-in [local KMS emulator](https://github.com/nsmithuk/local-kms), create
a signing key, and generate a Compose override with its public key and local trial
settings:

```shell
docker compose up -d kms
mkdir -p .state
docker compose run --rm --no-deps base python bin/dev-jwt-kms.py \
  > .state/jwt-kms.compose.json
docker compose --profile jwt-kms -f docker-compose.yml \
  -f .state/jwt-kms.compose.json up -d web
```

The emulator is reachable only inside the Compose network. The helper uses dummy
AWS credentials, creates a new key in the emulator, and writes a JSON document
that Compose can read as YAML. It contains a public key, not private key material.
The emulator's data volume persists between container restarts. For an existing
private Compose override, add `-f docker-compose.override.yaml` after the base
file; remove any old `JWT_SIGNING_KEY` entry before combining it with KMS.

To exercise rotation, create a second key while retaining the first public key,
then deploy the generated override. The old and new JWTs remain verifiable:

```shell
docker compose run --rm --no-deps base python bin/dev-jwt-kms.py \
  --rotate-from .state/jwt-kms.compose.json > .state/jwt-kms-next.compose.json
docker compose --profile jwt-kms -f docker-compose.yml \
  -f .state/jwt-kms-next.compose.json up -d web
```

The local issuer and audience strings are exact identifiers, not URLs Warehouse
fetches. Production environments must select their own distinct values and keys.

!!! warning "Development OIDC is deliberately insecure"

    `dev/environment` selects `NullOIDCPublisherService`, which skips upstream
    signature verification and replay protection. Use it only for private local
    development. The development debug toolbar also exposes application settings,
    including any PEM signing key.

    For shared trials, use a non-development configuration and
    `OIDC_BACKEND=warehouse.oidc.services.OIDCPublisherService`, with the normal
    publisher registration, provider configuration, and feature flags.

## Client protocol

Register a Trusted Publisher (or pending publisher) normally. Obtain a fresh
upstream OIDC assertion for the audience advertised by `GET /_/oidc/audience`.
That is the **upstream** audience (`OIDC_AUDIENCE`), not `JWT_UPLOAD_AUDIENCE`.
With the real OIDC backend, Warehouse checks the provider and publisher and rejects
reuse of an assertion that contains a `jti`. Assertions without a `jti` do not
receive this replay protection.

1. POST `/_/oidc/mint-token` with JSON
   `{"token": "<upstream OIDC assertion>", "token_format": "jwt"}`.
   The response retains `success`, `token`, and integer Unix `expires` fields.
   Issuance selects the publisher subject, upload audience, `projects:upload`
   permission, and five-minute lifetime on the server. Clients cannot choose
   claims or extend the lifetime.
2. Send the returned credential as `Authorization: Bearer <token>` on uploads.
   Do **not** pass it as the `__token__` password, a `Token` header, or a query
   parameter. The upstream OIDC assertion itself is not an upload credential.
3. POST `/_/oidc/burn-token` with JSON `{"token": "<Warehouse JWT>"}` after
   uploading, including in failure cleanup. No additional authentication header
   is needed. HTTP 202 is deliberately also returned for invalid, expired, or
   already-burned tokens; it is not proof the supplied credential was ever valid.
   A database/server failure must not be treated as successful revocation.

One JWT can upload to multiple projects currently associated with its publisher.
The token does not enumerate those projects. Removing a publisher association
removes that project's upload authorization; adding one makes it available to an
otherwise-valid token. Deleting the registry row revokes the token. Revocation
affects subsequent validation, not uploads already authorized and in progress.

A disabled JWT issuer returns HTTP 422 (`not-enabled`), without falling back to a
macaroon or consuming the upstream assertion. A KMS signing failure is a server
error and may consume the assertion's `jti`, if present; obtain a fresh assertion
before retrying. Do not silently retry without
`token_format`. Older servers may ignore an unknown request field and return a
macaroon: clients opting in must detect this instead of reporting a JWT trial as
successful. Omitted `token_format`, or explicit `"macaroon"`, keeps the existing
15-minute macaroon behavior.

### Minimal local client example

The example below uses Python with `requests` and runs from the checkout root.
It uploads the existing `sampleproject` source-distribution fixture to a local
instance where you have registered a matching publisher. Use an unused
project/version/artifact combination; this is not a general-purpose packaging
client. Set `WAREHOUSE_URL` to your local URL (including a non-default port, if
needed) and supply `OIDC_TOKEN` through your environment, not a command-line
argument or a checked-in file. On an instance using the null OIDC backend, test
assertions must still match a registered publisher; the integration tests above
create all required fixtures automatically.

This deliberately avoids `.netrc` credentials and redirects, keeps tokens out of
output, and burns the issued JWT even if the upload fails. Real remote clients
must use HTTPS and the correct authentication/upload hosts for their deployment.

```python
import hashlib
import os
from pathlib import Path

import requests

base = os.environ.get("WAREHOUSE_URL", "http://localhost").rstrip("/")
artifact = Path("tests/functional/_fixtures/sampleproject-3.0.0.tar.gz")
content = artifact.read_bytes()

with requests.Session() as client:
    client.trust_env = False  # No implicit .netrc auth or environment proxies.
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
    # The format check above is not cryptographic verification. Warehouse verifies
    # the credential when used; the client trusts its configured exchange server.
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

Keep the feature disabled outside an explicitly configured trial. Before a real
deployment, distribute the correct issuer, separate audiences, and public keys to
every verifier; give KMS signing access only to workloads that issue credentials.
Verification-only instances can omit signing settings. Confirm the
registry migration, cleanup worker, real OIDC backend, HTTPS endpoints, and client
Bearer support before inviting opt-in clients.

For production signing-key rotation, follow the [overlapping key procedure](../security/security-policy-flow.md#4d-jwtsecuritypolicy).

To stop a local trial, burn outstanding trial tokens first if you need their
registry rows removed immediately: disabling JWT verification also disables JWT
burning. Recreate the web service with your normal Compose configuration, excluding
the generated override, then stop the emulator with `docker compose stop kms`.
This restores the default disabled configuration; macaroon clients continue working.
The emulator keys remain in the Compose `jwt_kms_data` volume until you remove it.

Disabling JWTs does not itself delete registry rows or revoke unexpired tokens if
you re-enable the feature before they expire. Their short expiry bounds their
usability, and scheduled cleanup removes expired rows.

See [Security Policy Flow](../security/security-policy-flow.md#4d-jwtsecuritypolicy)
for the complete JWT profile, authorization rules, registry contract, and settings.
