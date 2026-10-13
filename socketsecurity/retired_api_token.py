import hashlib
import hmac
from typing import Optional

RETIRED_API_TOKEN_SHA256 = (
    "9cab58b24140ee12c08e265729d246f9200f8ef9b1d884f90c06c4e6b69adf18"
)
RETIRED_API_TOKEN_ERROR = (
    "This API token has been retired. Create a new API token in Socket "
    "and update your configuration."
)


# Fingerprint identifies a retired credential; it is not a password verifier.
def _matches_retired_digest(token: Optional[str], digest: str) -> bool:
    if token is None:
        return False
    token_digest = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    return hmac.compare_digest(token_digest, digest)


def _reject_retired_api_token(token: Optional[str], digest: str) -> None:
    if _matches_retired_digest(token, digest):
        raise ValueError(RETIRED_API_TOKEN_ERROR)


def reject_retired_api_token(token: Optional[str]) -> None:
    _reject_retired_api_token(token, RETIRED_API_TOKEN_SHA256)
