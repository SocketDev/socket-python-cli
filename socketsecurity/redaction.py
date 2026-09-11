"""Helpers for keeping credentials out of anything that reaches a log line.

The CLI runs inside other people's pipelines, and log output can be retained by
CI and forwarded elsewhere, so credentials must not reach it.

Nothing here tries to be a general-purpose scrubber. It covers the two shapes
the CLI actually holds: a config mapping with credential-ish field names, and a
webhook URL whose secret lives in the path.
"""

from typing import Any
from urllib.parse import urlsplit

REDACTED = "***redacted***"

# Substrings that mark a field name as carrying a credential. Matching on the
# name rather than an explicit allow-list means a field added later -- a
# `github_token`, say -- is covered without anyone remembering to come back here.
_SENSITIVE_NAME_MARKERS = (
    "apikey",
    "api_key",
    "auth",
    "credential",
    "passwd",
    "password",
    "secret",
    "token",
    "webhook",
)


def is_sensitive_name(name: str) -> bool:
    """Whether a field name looks like it holds a credential."""
    lowered = name.lower()
    return any(marker in lowered for marker in _SENSITIVE_NAME_MARKERS)


def redact_url(value: Any) -> Any:
    """Reduce a URL to scheme and host, dropping the parts that carry secrets.

    For webhook-style URLs the sensitive part is the path, so keeping the host
    preserves what a debug line is for -- seeing which endpoint is configured --
    without writing the rest.

    Values that are not absolute URLs are returned unchanged, so placeholders
    such as "Not configured" stay readable.
    """
    if not isinstance(value, str) or not value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return REDACTED
    if not parts.scheme or not parts.hostname:
        return value
    host = parts.hostname
    if parts.port:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}/{REDACTED}"


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Copy a mapping with credential-bearing values masked.

    Empty and unset values are left alone: "no token configured" is useful
    debugging information and is not a secret.
    """
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if not is_sensitive_name(key) or not value:
            redacted[key] = value
        elif isinstance(value, str) and urlsplit(value).scheme and urlsplit(value).hostname:
            redacted[key] = redact_url(value)
        else:
            redacted[key] = REDACTED
    return redacted
