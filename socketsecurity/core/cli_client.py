import base64
import json
import logging
from typing import Dict, List, Optional, Union

import requests

from socketsecurity import USER_AGENT
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
            'User-Agent': USER_AGENT,
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

    def post_telemetry_events(self, org_slug: str, events: List[Dict]) -> None:
        """Post telemetry events one at a time to the v0 telemetry API. Fire-and-forget — logs errors but never raises."""
        logger.debug(f"Sending {len(events)} telemetry event(s) to v0/orgs/{org_slug}/telemetry")
        for i, event in enumerate(events):
            try:
                logger.debug(f"Telemetry event {i+1}/{len(events)}: {json.dumps(event)}")
                resp = self.request(
                    path=f"orgs/{org_slug}/telemetry",
                    method="POST",
                    payload=json.dumps(event),
                )
                logger.debug(f"Telemetry event {i+1}/{len(events)} sent: status={resp.status_code}")
            except Exception as e:
                logger.warning(f"Failed to send telemetry event {i+1}/{len(events)}: {e}")
