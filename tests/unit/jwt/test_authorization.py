# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.common.db.accounts import UserFactory
from tests.common.db.macaroons import MacaroonFactory
from tests.common.db.oidc import GitHubPublisherFactory
from tests.common.db.packaging import ProjectFactory
from warehouse.accounts.utils import UserContext
from warehouse.authnz import Permissions
from warehouse.jwt.authorization import permits
from warehouse.jwt.claims import (
    AuthorizationDetail,
    AuthorizationType,
    ResourceKind,
    ResourceRef,
    SubjectKind,
    SubjectRef,
)
from warehouse.oidc.utils import PublisherTokenContext


@pytest.fixture
def identity(verified):
    return UserContext(UserFactory.build(id=verified.subject.id), macaroon=None)


def test_echo_needs_no_project(verified, identity):
    assert permits(verified, identity, None, Permissions.APIEcho)


def test_subject_kind_is_bound_even_with_the_same_uuid(verified, identity):
    publisher = GitHubPublisherFactory.build(id=identity.user.id)
    publisher_identity = PublisherTokenContext(publisher, claims=None)
    publisher_token = replace(
        verified, subject=SubjectRef(SubjectKind.PUBLISHER, publisher.id)
    )

    assert permits(publisher_token, publisher_identity, None, Permissions.APIEcho)
    assert not permits(publisher_token, identity, None, Permissions.APIEcho)
    assert not permits(verified, publisher_identity, None, Permissions.APIEcho)


def test_wrong_subject_id(verified, identity):
    token = replace(verified, subject=SubjectRef(SubjectKind.USER, uuid4()))
    assert not permits(token, identity, None, Permissions.APIEcho)


def test_macaroon_identity(verified, identity):
    macaroon = MacaroonFactory.build(user=identity.user)
    identity = replace(identity, macaroon=macaroon)
    assert not permits(verified, identity, None, Permissions.APIEcho)


def test_each_detail_keeps_its_actions_and_project_together(verified, identity):
    first = ProjectFactory.build()
    second = ProjectFactory.build()
    third = ProjectFactory.build()
    upload = AuthorizationDetail(
        AuthorizationType.WAREHOUSE,
        (Permissions.ProjectsUpload,),
        ResourceRef(ResourceKind.PROJECT, first.id),
    )
    token = replace(
        verified,
        authorization_details=(
            upload,
            replace(upload, resource=ResourceRef(ResourceKind.PROJECT, second.id)),
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE,
                (Permissions.APIObservationsAdd,),
                ResourceRef(ResourceKind.PROJECT, third.id),
            ),
        ),
    )

    assert permits(token, identity, first, Permissions.ProjectsUpload)
    assert permits(token, identity, second, Permissions.ProjectsUpload)
    assert not permits(token, identity, third, Permissions.ProjectsUpload)
    assert permits(token, identity, third, Permissions.APIObservationsAdd)
    assert not permits(token, identity, first, Permissions.APIObservationsAdd)


def test_permission_wide_observations_require_a_project(verified, identity):
    project = ProjectFactory.build()
    other = ProjectFactory.build()
    token = replace(
        verified,
        authorization_details=(
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE,
                (Permissions.ProjectsUpload,),
                ResourceRef(ResourceKind.PROJECT, project.id),
            ),
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.APIObservationsAdd,)
            ),
        ),
    )

    assert permits(token, identity, project, Permissions.APIObservationsAdd)
    assert permits(token, identity, other, Permissions.APIObservationsAdd)
    assert not permits(
        token, identity, SimpleNamespace(id=project.id), Permissions.APIObservationsAdd
    )
    assert permits(token, identity, project, Permissions.ProjectsUpload)
    assert not permits(token, identity, other, Permissions.ProjectsUpload)


def test_unsupported_permission(verified, identity):
    assert not permits(verified, identity, None, "api:echo")

    token = replace(
        verified,
        authorization_details=(
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE, (Permissions.AccountManage,)
            ),
        ),
    )
    assert not permits(token, identity, None, Permissions.AccountManage)
