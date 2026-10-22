# SPDX-License-Identifier: Apache-2.0

import base64
import hashlib
import io
import json
import tarfile

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid7

import jwt
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from freezegun import freeze_time
from sqlalchemy import func, select

from tests.common.constants import (
    DUMMY_ACTIVESTATE_OIDC_JWT,
    DUMMY_GITHUB_OIDC_JWT,
    DUMMY_GITLAB_OIDC_JWT,
    DUMMY_GOOGLE_OIDC_JWT,
)
from tests.common.db.accounts import UserFactory
from tests.common.db.oidc import (
    ActiveStatePublisherFactory,
    GitHubPublisherFactory,
    GitLabPublisherFactory,
    GooglePublisherFactory,
    PendingGitHubPublisherFactory,
)
from tests.common.db.packaging import ProjectFactory, RoleFactory
from tests.conftest import _make_webtest, get_app_config
from warehouse.events.tags import EventTag
from warehouse.jwt.models import IssuedJWT
from warehouse.oidc.services import OIDCPublisherService
from warehouse.packaging.models import File, Project

_ASSETS = Path(__file__).parents[1] / "_fixtures"
_GITHUB = {
    "repository_name": "bar",
    "repository_owner": "foo",
    "repository_owner_id": "123",
    "workflow_filename": "example.yml",
    "environment": "fake",
}


@pytest.fixture(scope="module")
def upstream_key():
    # Upstream OIDC and Warehouse-issued JWTs must use different signing keys.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def webtest(
    database, tm, warehouse_jwt_settings, upstream_key, mockredis, mocker, tmp_path
):
    # Real OIDC signature/claim verification, with local key discovery and an
    # in-memory replay cache. No request is made to a real identity provider.
    mocker.patch.object(
        OIDCPublisherService, "_get_key", return_value=upstream_key.public_key()
    )
    mocker.patch(
        "warehouse.oidc.services.redis", SimpleNamespace(StrictRedis=mockredis)
    )
    settings = {
        **warehouse_jwt_settings,
        "oidc.backend": "warehouse.oidc.services.OIDCPublisherService",
        "warehouse.db_create_session": lambda r: r.environ["warehouse.db_session"],
        "sessions.url": "redis://redis:0/",
        "files.path": str(tmp_path / "files"),
        "archive_files.path": str(tmp_path / "archive"),
    }
    yield from _make_webtest(get_app_config(database, settings), tm)


@pytest.fixture
def db(webtest):
    return webtest.extra_environ["warehouse.db_session"]


@pytest.fixture
def publisher(webtest):
    project = ProjectFactory(name="sampleproject")
    RoleFactory(
        project=project,
        user=UserFactory(with_verified_primary_email=True),
        role_name="Owner",
    )
    return GitHubPublisherFactory(projects=[project], **_GITHUB)


def assertion(key, template=DUMMY_GITHUB_OIDC_JWT):
    claims = jwt.decode(template, options={"verify_signature": False})
    now = int(datetime.now(UTC).timestamp())
    claims.update(iat=now, nbf=now, exp=now + 300, jti=str(uuid7()))
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "upstream"})


def exchange(webtest, upstream_key, template=DUMMY_GITHUB_OIDC_JWT):
    return webtest.post_json(
        "/_/oidc/mint-token",
        {"token": assertion(upstream_key, template), "token_format": "jwt"},
        status=200,
    ).json


def upload(
    webtest,
    token,
    *,
    name="sampleproject",
    version="3.0.0",
    scheme="Bearer",
    status=200,
    attestations=None,
):
    if name == "sampleproject" and version == "3.0.0":
        content = (_ASSETS / "sampleproject-3.0.0.tar.gz").read_bytes()
    else:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            files = {
                "PKG-INFO": (
                    f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                ).encode(),
                "README": b"JWT upload integration test",
            }
            for filename, data in files.items():
                member = tarfile.TarInfo(f"{name}-{version}/{filename}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        content = buffer.getvalue()
    params = {
        "name": name,
        "version": version,
        "metadata_version": "2.1",
        "filetype": "sdist",
        "sha256_digest": hashlib.sha256(content).hexdigest(),
    }
    if attestations is not None:
        params["attestations"] = attestations
    credentials = (
        base64.b64encode(f"__token__:{token}".encode()).decode()
        if scheme == "Basic"
        else token
    )
    return webtest.post(
        "/legacy/?:action=file_upload",
        headers={"Authorization": f"{scheme} {credentials}"},
        params=params,
        upload_files=[("content", f"{name}-{version}.tar.gz", content)],
        status=status,
    )


@pytest.mark.usefixtures("_enable_all_oidc_providers")
@pytest.mark.parametrize(
    ("factory", "data", "template"),
    [
        (GitHubPublisherFactory, _GITHUB, DUMMY_GITHUB_OIDC_JWT),
        (
            GitLabPublisherFactory,
            {
                "namespace": "foo",
                "project": "bar",
                "workflow_filepath": ".gitlab-ci.yml",
                "environment": "",
            },
            DUMMY_GITLAB_OIDC_JWT,
        ),
        (
            GooglePublisherFactory,
            {"email": "user@example.com", "sub": "111260650121185072906"},
            DUMMY_GOOGLE_OIDC_JWT,
        ),
        (
            ActiveStatePublisherFactory,
            {
                "organization": "fakeorg",
                "activestate_project_name": "fakeproject",
                "actor": "foo",
                "actor_id": "fake",
            },
            DUMMY_ACTIVESTATE_OIDC_JWT,
        ),
    ],
    ids=["github", "gitlab", "google", "activestate"],
)
def test_exchange_upload_history_and_burn(
    webtest, db, upstream_key, factory, data, template
):
    project = ProjectFactory(name="sampleproject")
    RoleFactory(
        project=project,
        user=UserFactory(with_verified_primary_email=True),
        role_name="Owner",
    )
    publisher = factory(projects=[project], **data)
    response = exchange(webtest, upstream_key, template)
    credential = response["token"]
    claims = jwt.decode(credential, options={"verify_signature": False})
    entry = db.get(IssuedJWT, UUID(claims["jti"]))
    assert entry.expires_at.timestamp() == response["expires"]
    upload(webtest, credential)
    file = project.releases[0].files[0]
    for event in (
        project.events.where(Project.Event.tag == EventTag.Project.ReleaseAdd).one(),
        file.events.where(File.Event.tag == EventTag.File.FileAdd).one(),
    ):
        assert event.additional["uploaded_via_trusted_publisher"] is True
        assert event.additional["publisher_url"] == publisher.publisher_url(
            entry.additional["oidc"]
        )
    webtest.post_json("/_/oidc/burn-token", {"token": credential}, status=202)
    assert db.scalar(select(IssuedJWT.id).where(IssuedJWT.id == entry.id)) is None
    upload(webtest, credential, version="3.0.1", status=403)
    assert len(project.releases) == 1


def test_publisher_jwt_preserves_attestation_provenance(
    webtest, publisher, upstream_key
):
    credential = exchange(webtest, upstream_key)["token"]
    contents = (_ASSETS / "sampleproject-3.0.0.tar.gz.publish.attestation").read_text()
    upload(webtest, credential, attestations=f"[{contents}]")
    provenance = publisher.projects[0].releases[0].files[0].provenance.provenance
    bundle = provenance["attestation_bundles"][0]
    assert bundle["publisher"] == publisher.attestation_identity.model_dump(mode="json")
    assert bundle["attestations"] == [json.loads(contents)]


def test_permission_wide_upload_follows_live_membership(
    webtest, db, publisher, upstream_key
):
    credential = exchange(webtest, upstream_key)["token"]
    first = publisher.projects[0]
    second = ProjectFactory(name="secondproject", oidc_publishers=[publisher])
    RoleFactory(
        project=second,
        user=UserFactory(with_verified_primary_email=True),
        role_name="Owner",
    )
    upload(webtest, credential)
    upload(webtest, credential, name=second.name, version="1.0.0")
    publisher.projects.remove(first)
    db.flush()
    upload(webtest, credential, version="3.0.1", status=403)
    unrelated = ProjectFactory(name="unrelatedproject")
    upload(webtest, credential, name=unrelated.name, version="1.0.0", status=403)
    assert len(first.releases) == len(second.releases) == 1


@pytest.mark.parametrize("scheme", ["Basic", "Token"])
def test_jwt_requires_bearer(webtest, publisher, upstream_key, scheme):
    credential = exchange(webtest, upstream_key)["token"]
    upload(webtest, credential, scheme=scheme, status=403)
    assert not publisher.projects[0].releases


def test_upstream_oidc_is_not_an_upload_credential(webtest, publisher, upstream_key):
    upload(webtest, assertion(upstream_key), status=403)


def test_expiration_is_enforced_without_cleanup(webtest, publisher, upstream_key, db):
    with freeze_time(datetime.now(UTC), ignore=["_pytest"]) as clock:
        response = exchange(webtest, upstream_key)
        clock.move_to(datetime.fromtimestamp(response["expires"], UTC))
        upload(webtest, response["token"], status=403)
        assert db.scalar(select(func.count()).select_from(IssuedJWT)) == 1


def test_upload_jwt_cannot_authenticate_to_api(webtest, publisher, upstream_key):
    credential = exchange(webtest, upstream_key)["token"]
    webtest.get(
        "/danger-api/echo",
        headers={"Authorization": f"Bearer {credential}"},
        status=403,
    )


@pytest.mark.parametrize("field", ["aud", "authorization_details"])
def test_upload_requires_upload_audience_and_permission(
    webtest, publisher, upstream_key, warehouse_jwt_key, warehouse_jwt_settings, field
):
    credential = exchange(webtest, upstream_key)["token"]
    claims = jwt.decode(credential, options={"verify_signature": False})
    claims[field] = {
        "aud": warehouse_jwt_settings["warehouse.jwt.api_audience"],
        "authorization_details": [{"type": "warehouse", "actions": ["api:echo"]}],
    }[field]
    credential = jwt.encode(
        claims,
        warehouse_jwt_key,
        algorithm="RS256",
        headers=jwt.get_unverified_header(credential),
    )
    upload(webtest, credential, status=403)
    assert not publisher.projects[0].releases


def test_deleted_publisher_cannot_upload(webtest, db, publisher, upstream_key):
    credential = exchange(webtest, upstream_key)["token"]
    db.delete(publisher)
    db.flush()
    upload(webtest, credential, status=403)


def test_unknown_or_unregistered_credentials_cannot_upload(
    webtest, publisher, upstream_key, db
):
    credential = exchange(webtest, upstream_key)["token"]
    entry = db.scalar(select(IssuedJWT))
    db.delete(entry)
    db.flush()
    upload(webtest, credential, status=403)
    upload(webtest, "invalid.jwt.token", status=403)


def test_replay_protection_spans_token_formats(webtest, publisher, upstream_key):
    upstream = assertion(upstream_key)
    webtest.post_json(
        "/_/oidc/mint-token", {"token": upstream, "token_format": "jwt"}, status=200
    )
    for payload in ({"token": upstream}, {"token": upstream, "token_format": "jwt"}):
        response = webtest.post_json("/_/oidc/mint-token", payload, status=422)
        assert response.json["errors"][0]["code"] == "invalid-reuse-token"


def test_default_macaroon_flow_is_unchanged_when_jwt_enabled(
    webtest, publisher, upstream_key
):
    response = webtest.post_json(
        "/_/oidc/mint-token", {"token": assertion(upstream_key)}, status=200
    )
    credential = response.json["token"]
    assert credential.startswith("pypi-")
    upload(webtest, credential, scheme="Basic")
    webtest.post_json("/_/oidc/burn-token", {"token": credential}, status=202)
    upload(webtest, credential, scheme="Basic", version="3.0.1", status=403)


def test_pending_publisher_jwt_can_upload(webtest, db, upstream_key):
    PendingGitHubPublisherFactory(
        project_name="sampleproject",
        added_by=UserFactory(with_verified_primary_email=True),
        **_GITHUB,
    )
    credential = exchange(webtest, upstream_key)["token"]
    upload(webtest, credential)
    project = db.scalar(select(Project).where(Project.name == "sampleproject"))
    assert len(project.releases) == 1
