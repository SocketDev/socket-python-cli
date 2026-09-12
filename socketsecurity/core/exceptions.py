from socketdev.exceptions import APIFailure as SdkAPIFailure

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


class APIFailure(SdkAPIFailure):
    """Raised when there is an error using the API.

    Subclasses the SDK's exception of the same name so a handler written against
    either one catches both. They were independent Exception subclasses, so an
    ``except APIFailure`` importing the SDK's -- which every handler in
    socketsecurity.core does -- silently let a CliClient failure through, and the
    status code the SDK class carries was unavailable to anything raised here.
    """
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

class RequestTimeoutExceeded(Exception):
    """Raised when access is denied to the API"""
    pass