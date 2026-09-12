"""Tests for the shared git remote parser.

Both the GitHub comment adapter (`GithubConfig._repository_from_buildkite`) and
pull request URL construction depend on this, so the URL forms Buildkite and
self-hosted installations emit are pinned here rather than in either caller.
"""
import pytest

from socketsecurity.core.git_remote import parse_git_remote


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        # The three forms BUILDKITE_REPO is observed to take.
        ("git@github.com:acme/widgets.git", ("github.com", "acme/widgets")),
        ("https://github.com/acme/widgets.git", ("github.com", "acme/widgets")),
        ("ssh://git@github.com/acme/widgets.git", ("github.com", "acme/widgets")),
        # Self-hosted hosts must survive: they decide the PR/MR link's origin.
        ("git@github.example.com:acme/widgets.git", ("github.example.com", "acme/widgets")),
        ("https://gitlab.example.com/acme/widgets", ("gitlab.example.com", "acme/widgets")),
        # GitLab subgroups: the path is returned whole, not just the last two parts.
        (
            "ssh://git@gitlab.example.com/acme/platform/widgets.git",
            ("gitlab.example.com", "acme/platform/widgets"),
        ),
        ("git://github.com/acme/widgets.git", ("github.com", "acme/widgets")),
        # Cosmetic variation callers should not have to normalise themselves.
        ("  https://github.com/acme/widgets/  ", ("github.com", "acme/widgets")),
        # Credentials in the URL must not leak into the host.
        ("https://user@github.com/acme/widgets", ("github.com", "acme/widgets")),
        # A bare slug carries no host to report, but is still usable.
        ("acme/widgets", (None, "acme/widgets")),
        # Nothing usable.
        ("not-a-repository", (None, None)),
        ("", (None, None)),
        (None, (None, None)),
    ],
)
def test_parse_git_remote(remote, expected):
    assert parse_git_remote(remote) == expected
