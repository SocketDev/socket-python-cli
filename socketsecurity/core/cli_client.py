import base64
import logging
from typing import Dict, List, Optional, Union

import requests

from .exceptions import APIFailure
from .socket_config import SocketConfig

logger = logging.getLogger("socketdev")

class CliClient:
    def __init__(self, config: SocketConfig):
        self.config = config
        self._encoded_key = self._encode_key(config.api_key)

    @staticmethod
    def _encode_key(token: str) -> str:
        return base64.b64encode(f"{token}:".encode()).decode('ascii')

    def request(
        self,
        path: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        payload: Optional[Union[Dict, str]] = None,
        files: Optional[List] = None,
        base_url: Optional[str] = None
    ) -> requests.Response:
        url = f"{base_url or self.config.api_url}/{path}"

        default_headers = {
            'Authorization': f"Basic {self._encoded_key}",
            'User-Agent': 'SocketPythonCLI/0.0.1',
            "accept": "application/json"
        }

        headers = headers or default_headers

        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                data=payload,
                files=files,
                timeout=self.config.timeout,
                verify=not self.config.allow_unverified_ssl
            )

            response.raise_for_status()
            return response

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            raise APIFailure(f"Request failed: {str(e)}")
