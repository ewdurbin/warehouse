# Trusted Publisher JWT trial

This is an opt-in developer trial, not an announcement of availability on PyPI.
JWT verification and issuance remain **disabled by default**. Existing clients
continue to receive macaroons unless they explicitly request `"token_format": "jwt"`.
The trial issues only publisher-backed upload credentials, not user credentials
or danger-API credentials.

## Run the local integration tests

With the [Compose development setup](getting-started.md) built, run:

```shell
docker compose run --rm -T \
  -e PYTHONPATH=/opt/warehouse/src/pyramid_components/src:/opt/warehouse/src \
  tests python -m pytest --postgresql-host db -n 0 -q \
  tests/functional/forklift/test_jwt.py
```

This uses a temporary **test database on Compose's PostgreSQL service**, not the
development database. It does not change your web server's configuration or
require a signing key in `.env`. The tests generate separate ephemeral RSA keys
for the upstream OIDC assertion and Warehouse-issued JWT, exercise real signature
and publisher-claim verification, and replace upstream key discovery and the
OIDC replay cache with local test doubles. Attestation tests use the existing
development integrity service; they test provenance plumbing, not attestation
signature verification.

The tests cover exchange, Bearer upload, pending publishers, upload history,
provenance, live multi-project access, self-revocation, expiry, audience separation,
replay protection across credential formats, and the unchanged macaroon flow.

## Enable a local web-server trial

Apply the registry migrations with `make runmigrations` before issuing tokens.
The registry and its `additional` metadata column must exist on every deployment
using the feature.

Generate a **local-only** key pair using OpenSSL, keeping the private key outside
the checkout. Do not reuse production keys, enable shell tracing, print these
environment variables, or include them in bug reports:

```shell
umask 077
jwt_trial_dir="$(mktemp -d)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$jwt_trial_dir/private.pem"
openssl pkey -in "$jwt_trial_dir/private.pem" -pubout \
  -out "$jwt_trial_dir/public.pem"

export JWT_ENABLED=true
export JWT_ISSUER=urn:warehouse:local
export JWT_UPLOAD_AUDIENCE=urn:warehouse:local:upload
export JWT_API_AUDIENCE=urn:warehouse:local:api
export JWT_SIGNING_KEY_ID=local-trial
export JWT_SIGNING_KEY="$(cat "$jwt_trial_dir/private.pem")"
export JWT_VERIFICATION_KEYS="$(python3 -c \
  'import json, sys; print(json.dumps({"local-trial": sys.stdin.read()}))' \
  < "$jwt_trial_dir/public.pem")"
```

These issuer/audience strings are exact identifiers, not URLs Warehouse fetches.
Choose different values for each environment; upload and API audiences must also
be distinct. Both audience settings are required even for this upload-only trial.

Compose does not automatically forward every shell or `.env` variable into the
web container. Merge this mapping into your **private** Compose override, preserving
any existing settings:

```yaml
services:
  web:
    environment:
      JWT_ENABLED: "${JWT_ENABLED:-false}"
      JWT_ISSUER: "${JWT_ISSUER:?set JWT_ISSUER}"
      JWT_UPLOAD_AUDIENCE: "${JWT_UPLOAD_AUDIENCE:?set JWT_UPLOAD_AUDIENCE}"
      JWT_API_AUDIENCE: "${JWT_API_AUDIENCE:?set JWT_API_AUDIENCE}"
      JWT_VERIFICATION_KEYS: "${JWT_VERIFICATION_KEYS:?set JWT_VERIFICATION_KEYS}"
      JWT_SIGNING_KEY_ID: "${JWT_SIGNING_KEY_ID:?set JWT_SIGNING_KEY_ID}"
      JWT_SIGNING_KEY: "${JWT_SIGNING_KEY:?set JWT_SIGNING_KEY}"
```

Recreate the web service with `docker compose up -d --no-deps --force-recreate web`.
A restart alone does not update container environment variables. Do not paste
`docker compose config` output: it can contain the private key.

!!! warning "Development OIDC is deliberately insecure"

    `dev/environment` selects `NullOIDCPublisherService`, which skips upstream
    signature verification and replay protection. It is suitable only for a
    private local development instance. Any real CI or shared-environment trial
    must use `OIDC_BACKEND=warehouse.oidc.services.OIDCPublisherService`, with the
    normal trusted publisher registration, provider configuration, and feature
    flags. Warehouse JWT signing does not make the null upstream verifier safe.

## Client protocol

Register a Trusted Publisher (or pending publisher) normally. Obtain a fresh
upstream OIDC assertion for the audience advertised by `GET /_/oidc/audience`.
That is the **upstream** audience (`OIDC_AUDIENCE`), not `JWT_UPLOAD_AUDIENCE`.
The normal provider/publisher checks and single-use replay protection still apply.

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

An unavailable JWT issuer returns HTTP 422 (`not-enabled`), without falling back
to a macaroon or consuming the upstream assertion. Do not silently retry without
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
every verifier; supply the matching private key only where issuance is needed.
Verification-only instances can omit **both** signing settings. Confirm the
registry migrations, cleanup worker, real OIDC backend, HTTPS endpoints, and client
Bearer support before inviting opt-in clients. This branch does not update
external publishing clients or provide secret-scanning integration for JWTs.

For normal signing-key rotation, change the active key ID/private key while
retaining old public keys for at least the remaining five-minute token lifetime
after the last old-key issuer stops. Retire a compromised key immediately instead.

To stop a local trial, set `JWT_ENABLED=false` and recreate the web service;
macaroon clients continue working. Disabling JWT verification also disables JWT
burning, so burn outstanding trial tokens first if you need their registry rows
removed immediately. Otherwise their short expiry still bounds their usability,
and scheduled cleanup removes expired rows. Disabling JWTs does not itself delete
rows or revoke unexpired tokens if you re-enable the feature before they expire.
Remove local private keys and exported signing variables when finished.

See [Security Policy Flow](../security/security-policy-flow.md#4d-jwtsecuritypolicy)
for the complete JWT profile, authorization rules, registry contract, and settings.
