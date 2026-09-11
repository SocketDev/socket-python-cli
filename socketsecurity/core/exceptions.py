__all__ = [
    "APIAccessDenied",
    "APICloudflareError",
    "APIFailure",
    "APIInsufficientQuota",
    "APIKeyMissing",
    "APIResourceNotFound",
]


class APICloudflareError(Exception):
    """Raised when there is an error using the API related to cloudflare"""


class APIKeyMissing(Exception):
    """Raised when the api key is not passed and the headers are empty"""


class APIFailure(Exception):
    """Raised when there is an error using the API"""


class APIAccessDenied(Exception):
    """Raised when access is denied to the API"""


class APIInsufficientQuota(Exception):
    """Raised when access is denied to the API"""


class APIResourceNotFound(Exception):
    """Raised when access is denied to the API"""


class RequestTimeoutExceeded(Exception):
    """Raised when access is denied to the API"""
