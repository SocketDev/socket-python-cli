__all__ = [
    "APIFailure",
    "APIKeyMissing",
    "APIAccessDenied",
    "APIInsufficientQuota",
    "APIResourceNotFound",
    "APICloudflareError"
]


class APICloudflareError(Exception):
    """Raised when there is an error using the API related to cloudflare"""
    pass


class APIKeyMissing(Exception):
    """Raised when the api key is not passed and the headers are empty"""
    pass


class APIFailure(Exception):
    """Raised when there is an error using the API"""
    pass


class APIAccessDenied(Exception):
    """Raised when access is denied to the API"""
    pass


class APIInsufficientQuota(Exception):
    """Raised when access is denied to the API"""
    pass


class APIResourceNotFound(Exception):
    """Raised when access is denied to the API"""
    pass
