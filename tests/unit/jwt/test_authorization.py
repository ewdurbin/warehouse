# SPDX-License-Identifier: Apache-2.0

import types

from dataclasses import replace
from uuid import uuid4

import pytest

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
from warehouse.packaging.models import Project


@pytest.fixture
def identity(verified):
    return UserContext(types.SimpleNamespace(id=verified.subject.id), macaroon=None)


@pytest.fixture
def project(verified, mocker):
    return mocker.Mock(spec=Project, id=verified.authorization_details[0].resource.id)


@pytest.mark.parametrize(
    "permission", [Permissions.ProjectsUpload, Permissions.APIObservationsAdd]
)
def test_project_scope(verified, identity, project, permission):
    assert permits(verified, identity, project, permission)
    assert not permits(
        verified, identity, types.SimpleNamespace(id=project.id), permission
    )
    project.id = uuid4()
    assert not permits(verified, identity, project, permission)


def test_echo_needs_no_project(verified, identity):
    verified = replace(
        verified,
        authorization_details=(
            AuthorizationDetail(AuthorizationType.WAREHOUSE, (Permissions.APIEcho,)),
        ),
    )
    assert permits(verified, identity, None, Permissions.APIEcho)


@pytest.mark.parametrize(
    "permission", [Permissions.ProjectsUpload, Permissions.APIObservationsAdd]
)
def test_missing_permission(verified, identity, project, permission):
    verified = replace(
        verified,
        authorization_details=(
            AuthorizationDetail(AuthorizationType.WAREHOUSE, (Permissions.APIEcho,)),
        ),
    )
    assert not permits(verified, identity, project, permission)


@pytest.mark.parametrize("permission", [Permissions.AccountManage, "api:echo", "*"])
def test_unsupported_permission(verified, identity, permission):
    assert not permits(verified, identity, None, permission)


@pytest.mark.parametrize("identity", [None, types.SimpleNamespace()])
def test_unsupported_identity(verified, identity):
    assert not permits(verified, identity, None, Permissions.APIEcho)


def test_wrong_user(verified, identity):
    identity.user.id = uuid4()
    assert not permits(verified, identity, None, Permissions.APIEcho)


def test_macaroon_identity(verified, identity):
    identity.macaroon = object()
    assert not permits(verified, identity, None, Permissions.APIEcho)


@pytest.mark.parametrize("matches", [True, False])
def test_publisher_binding(verified, project, matches):
    verified = replace(
        verified, subject=SubjectRef(SubjectKind.PUBLISHER, verified.subject.id)
    )
    identity = PublisherTokenContext(
        types.SimpleNamespace(id=verified.subject.id if matches else uuid4()),
        claims=None,
    )
    assert permits(verified, identity, project, Permissions.ProjectsUpload) == matches


@pytest.mark.parametrize("kind", [SubjectKind.USER, SubjectKind.PUBLISHER])
def test_same_uuid_cannot_cross_subject_kinds(verified, identity, kind):
    subject = SubjectRef(kind, verified.subject.id)
    if kind == SubjectKind.USER:
        identity = PublisherTokenContext(identity.user, claims=None)
    assert not permits(
        replace(verified, subject=subject), identity, None, Permissions.APIEcho
    )


def test_unknown_subject_kind(verified, identity):
    verified = replace(
        verified, subject=SubjectRef("organization", verified.subject.id)
    )
    assert not permits(verified, identity, None, Permissions.APIEcho)


def test_details_do_not_form_a_cross_product(verified, identity, project, mocker):
    other = mocker.Mock(spec=Project, id=uuid4())
    verified = replace(
        verified,
        authorization_details=(
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE,
                (Permissions.ProjectsUpload,),
                ResourceRef(ResourceKind.PROJECT, project.id),
            ),
            AuthorizationDetail(
                AuthorizationType.WAREHOUSE,
                (Permissions.APIObservationsAdd,),
                ResourceRef(ResourceKind.PROJECT, other.id),
            ),
        ),
    )
    assert permits(verified, identity, project, Permissions.ProjectsUpload)
    assert permits(verified, identity, other, Permissions.APIObservationsAdd)
    assert not permits(verified, identity, other, Permissions.ProjectsUpload)
    assert not permits(verified, identity, project, Permissions.APIObservationsAdd)


@pytest.mark.parametrize(
    ("permission", "kind"),
    [
        (Permissions.ProjectsUpload, "organization"),
        (Permissions.AccountManage, ResourceKind.PROJECT),
        (Permissions.APIEcho, ResourceKind.PROJECT),
    ],
)
def test_unsupported_detail_never_allows(verified, identity, project, permission, kind):
    detail = AuthorizationDetail(
        AuthorizationType.WAREHOUSE, (permission,), ResourceRef(kind, project.id)
    )
    assert not permits(
        replace(verified, authorization_details=(detail,)),
        identity,
        project,
        permission,
    )


class TestPermissionWideAuthorization:
    @pytest.mark.parametrize(
        "permission", [Permissions.ProjectsUpload, Permissions.APIObservationsAdd]
    )
    @pytest.mark.parametrize("kind", [SubjectKind.USER, SubjectKind.PUBLISHER])
    def test_any_project_with_matching_subject(
        self, verified, identity, project, permission, kind
    ):
        token = replace(
            verified,
            subject=SubjectRef(kind, verified.subject.id),
            authorization_details=(
                AuthorizationDetail(AuthorizationType.WAREHOUSE, (permission,)),
            ),
        )
        if kind == SubjectKind.PUBLISHER:
            identity = PublisherTokenContext(identity.user, claims=None)
        # Scope matching does not establish the live ACL privileges.
        assert permits(token, identity, project, permission)
        project.id = uuid4()
        assert permits(token, identity, project, permission)

    @pytest.mark.parametrize(
        "permission", [Permissions.ProjectsUpload, Permissions.APIObservationsAdd]
    )
    def test_requires_project_context(self, verified, identity, project, permission):
        token = replace(
            verified,
            authorization_details=(
                AuthorizationDetail(AuthorizationType.WAREHOUSE, (permission,)),
            ),
        )
        assert not permits(token, identity, None, permission)
        assert not permits(
            token, identity, types.SimpleNamespace(id=project.id), permission
        )

    def test_unknown_detail_type(self, verified, identity, project):
        token = replace(
            verified,
            authorization_details=(
                AuthorizationDetail("unknown", (Permissions.APIObservationsAdd,)),
            ),
        )
        assert not permits(token, identity, project, Permissions.APIObservationsAdd)

    def test_unsupported_permission(self, verified, identity, project):
        token = replace(
            verified,
            authorization_details=(
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE, (Permissions.AccountManage,)
                ),
            ),
        )
        assert not permits(token, identity, project, Permissions.AccountManage)

    def test_details_are_additive(self, verified, identity, project):
        token = replace(
            verified,
            authorization_details=(
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.APIObservationsAdd,),
                    ResourceRef(ResourceKind.PROJECT, uuid4()),
                ),
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE, (Permissions.APIObservationsAdd,)
                ),
            ),
        )
        assert permits(token, identity, project, Permissions.APIObservationsAdd)

    def test_does_not_widen_other_operations(self, verified, identity, project, mocker):
        other = mocker.Mock(spec=Project, id=uuid4())
        token = replace(
            verified,
            authorization_details=(
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE, (Permissions.ProjectsUpload,)
                ),
                AuthorizationDetail(
                    AuthorizationType.WAREHOUSE,
                    (Permissions.APIObservationsAdd,),
                    ResourceRef(ResourceKind.PROJECT, project.id),
                ),
            ),
        )
        assert permits(token, identity, project, Permissions.ProjectsUpload)
        assert permits(token, identity, other, Permissions.ProjectsUpload)
        assert permits(token, identity, project, Permissions.APIObservationsAdd)
        assert not permits(token, identity, other, Permissions.APIObservationsAdd)
