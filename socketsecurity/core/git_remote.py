"""Parsing for git remote URLs.

CI systems that are not tied to a single SCM expose the checkout URL rather than
an ``owner/repo`` slug (Buildkite's ``BUILDKITE_REPO``, for example). Both the
GitHub comment adapter and pull request context resolution need to recover the
slug from it, so the parsing lives here rather than in either caller.
"""
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# git@host:owner/repo - the scp-like syntax urlparse cannot handle. The negative
# lookahead keeps scheme-prefixed URLs (https://, ssh://) out of this branch.
_SCP_LIKE_REMOTE = re.compile(r"^(?:[^@/]+@)?([^:/]+):(?!//)(.+)$")


def parse_git_remote(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Split a git remote URL into its host and its repository path.

    Returns ``(host, path)``, or ``(None, None)`` when the value is not a usable
    remote. The path is returned whole rather than as ``owner``/``repo`` because
    GitLab projects can be nested under subgroups; callers that only want the
    last two segments can split it themselves. ``host`` is ``None`` for a bare
    ``owner/repo`` path, which carries no host to report.
    """
    if not value:
        return None, None
    url = value.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    match = _SCP_LIKE_REMOTE.match(url)
    if match:
        return match.group(1), match.group(2).strip("/")

    parsed = urlparse(url)
    if parsed.scheme in ("http", "https", "ssh", "git") and parsed.hostname:
        return parsed.hostname, parsed.path.strip("/")

    # A bare owner/repo path, with no scheme and nothing to infer a host from.
    if "/" in url:
        return None, url.strip("/")
    return None, None
