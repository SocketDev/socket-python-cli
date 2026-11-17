"""Mask credential fields and integration URL paths in debug logging."""

from typing import Any
from urllib.parse import urlsplit

REDACTED = "***redacted***"

# Match credential-bearing field names, including nested plugin settings.
_SENSITIVE_NAME_MARKERS = (
    "apikey",
    "api_key",
    "auth",
    "credential",
    "passwd",
    "password",
    "secret",
    "token",
    "url",
    "webhook",
)


def is_sensitive_name(name: str) -> bool:
    """Whether a field name looks like it holds a credential."""
    lowered = name.lower()
    # The ignore-command authorization policy is public configuration.
    if lowered == "ignore_authorization":
        return False
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
        host = parts.hostname
        port = parts.port
    except ValueError:
        return REDACTED
    if not parts.scheme or not host:
        return value
    if ":" in host:
        host = f"[{host}]"
    if port:
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}/{REDACTED}"


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Copy a mapping, masking credential fields recursively.

    Empty and unset values are left alone: "no token configured" is useful
    debugging information and is not a secret.
    """
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if not value:
            redacted[key] = value
        elif is_sensitive_name(key):
            redacted[key] = _redact_sensitive_value(value)
        else:
            redacted[key] = _redact_nested(value)
    return redacted


def _redact_sensitive_value(value: Any) -> str:
    if isinstance(value, str):
        try:
            parts = urlsplit(value)
            if parts.scheme and parts.hostname:
                return redact_url(value)
        except ValueError:
            pass
    return REDACTED


def _redact_nested(value: Any) -> Any:
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_nested(item) for item in value)
    return value
