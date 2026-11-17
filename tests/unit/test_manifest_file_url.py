"""Manifest links use the configured SCM and resolved repository URL."""

from dataclasses import dataclass

import pytest

from socketsecurity.core.classes import Diff
from socketsecurity.core.messages import Messages

SOCKET_REPORT = "https://socket.dev/dashboard/org/acme/sbom/abc123"


@dataclass
class _Config:
    scm: str = "api"
    repo: str = "widgets"
    repository_url: str = "https://github.com/acme/widgets"
    branch: str = "main"


def _diff(diff_url: str = "https://socket.dev/dashboard/org/acme/diff/h1/abc123") -> Diff:
    return Diff(id="abc123", diff_url=diff_url, report_url=SOCKET_REPORT)


def test_github_url_is_built_from_config_not_diff_url():
    url = Messages.get_manifest_file_url(_diff(), "package.json", _Config(scm="github"))
    assert url == "https://github.com/acme/widgets/blob/main/package.json"


def test_github_enterprise_uses_resolved_repository_url():
    url = Messages.get_manifest_file_url(
        _diff(), "package.json", _Config(scm="github", repository_url="https://github.mycorp.com/acme/widgets")
    )
    assert url == "https://github.mycorp.com/acme/widgets/blob/main/package.json"


def test_gitlab_uses_blob_path_and_resolved_repository_url():
    url = Messages.get_manifest_file_url(
        _diff(), "go.mod", _Config(scm="gitlab", branch="dev", repository_url="https://gitlab.mycorp.com/acme/widgets")
    )
    assert url == "https://gitlab.mycorp.com/acme/widgets/-/blob/dev/go.mod"


def test_bitbucket_uses_src_path():
    url = Messages.get_manifest_file_url(
        _diff(), "pom.xml", _Config(scm="bitbucket", repository_url="https://bitbucket.org/acme/widgets")
    )
    assert url == "https://bitbucket.org/acme/widgets/src/main/pom.xml"


def test_scm_is_case_insensitive():
    url = Messages.get_manifest_file_url(_diff(), "package.json", _Config(scm="GitHub"))
    assert url.startswith("https://github.com/")


@pytest.mark.parametrize("scm", ["api", "", "unknown"])
def test_non_scm_types_fall_back_to_the_socket_file_view(scm):
    url = Messages.get_manifest_file_url(_diff(), "src/package.json", _Config(scm=scm))
    assert url == f"{SOCKET_REPORT}?tab=files&file=src%2Fpackage.json"


def test_missing_config_falls_back_to_the_socket_file_view():
    url = Messages.get_manifest_file_url(_diff(), "package.json", None)
    assert url == f"{SOCKET_REPORT}?tab=files&file=package.json"


class _ConfigWithoutScm:
    """Repository metadata without an SCM type."""

    repo = "acme/widgets"
    branch = "main"


def test_config_without_an_scm_attribute_falls_back_to_socket():
    url = Messages.get_manifest_file_url(_diff(), "package.json", _ConfigWithoutScm())
    assert url == f"{SOCKET_REPORT}?tab=files&file=package.json"


@pytest.mark.parametrize(
    "diff_url",
    [
        "https://socket.dev/dashboard/org/github-tools/diff/h1/abc123",
        "https://socket.dev/dashboard/org/our-gitlab-org/diff/h1/abc123",
        "https://socket.dev/dashboard/org/bitbucket-team/diff/h1/abc123",
    ],
)
def test_org_slug_containing_an_scm_name_does_not_change_the_url(diff_url):
    """Socket organization slugs do not determine the repository provider."""
    url = Messages.get_manifest_file_url(_diff(diff_url), "package.json", _ConfigWithoutScm())
    assert url == f"{SOCKET_REPORT}?tab=files&file=package.json"


def test_first_manifest_is_used_when_several_are_joined():
    url = Messages.get_manifest_file_url(_diff(), "a/package.json;b/yarn.lock", _Config(scm="github"))
    assert url == "https://github.com/acme/widgets/blob/main/a/package.json"


@pytest.mark.parametrize(
    "raw",
    [
        "home/runner/work/widgets/widgets/src/package.json",
        "/home/runner/work/widgets/widgets/src/package.json",
        "opt/buildagent/work/abc123/widgets/src/package.json",
    ],
)
def test_build_agent_prefixes_are_stripped(raw):
    url = Messages.get_manifest_file_url(_diff(), raw, _Config(scm="github"))
    assert url == "https://github.com/acme/widgets/blob/main/src/package.json"


def test_empty_manifest_path_returns_empty_string():
    assert Messages.get_manifest_file_url(_diff(), "", _Config(scm="github")) == ""
