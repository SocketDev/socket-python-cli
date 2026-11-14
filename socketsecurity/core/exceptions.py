from socketdev.exceptions import APIFailure as SdkAPIFailure

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


class APIFailure(SdkAPIFailure):
    """Raised when there is an error using the API.

    Subclasses the SDK's exception of the same name so a handler written against
    either one catches both. A separate Exception subclass would bypass an
    ``except APIFailure`` importing the SDK's -- which every handler in
    socketsecurity.core does -- and would not carry the SDK class's status code.
    """


class APIAccessDenied(Exception):
    """Raised when access is denied to the API"""


class APIInsufficientQuota(Exception):
    """Raised when access is denied to the API"""


class APIResourceNotFound(Exception):
    """Raised when access is denied to the API"""


class RequestTimeoutExceeded(Exception):
    """Raised when access is denied to the API"""
