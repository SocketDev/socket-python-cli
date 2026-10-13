from typing import Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


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
