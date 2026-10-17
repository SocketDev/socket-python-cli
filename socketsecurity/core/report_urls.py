from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class AlertLinks:
    package_url: Optional[str]
    info_url: Optional[str]


def build_alert_links(
    package_url: Optional[str], alert_type: Optional[str]
) -> AlertLinks:
    return AlertLinks(
        package_url=package_url or None,
        info_url=(
            f"https://socket.dev/alerts/{quote(alert_type, safe='')}"
            if alert_type
            else None
        ),
    )


def add_query_params(
    url: Optional[str], params: Mapping[str, str]
) -> Optional[str]:
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    replaced_keys = set(params)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key not in replaced_keys
    ]
    query.extend(params.items())
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )
