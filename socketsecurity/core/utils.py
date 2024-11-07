import base64
import requests
from typing import Optional, Dict, List, Union
from socketsecurity import __version__
from socketsecurity.core.exceptions import APIKeyMissing

def encode_key(token: str) -> str:
    """Encode API token in base64"""
    return base64.b64encode(token.encode()).decode('ascii')

def do_request(
        path: str,
        headers: Optional[Dict] = None,
        payload: Optional[Union[Dict, str]] = None,
        files: Optional[List] = None,
        method: str = "GET",
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = True
) -> requests.Response:
    """Make HTTP requests to Socket API"""

    if base_url is not None:
        url = f"{base_url}/{path}"
    else:
        if not api_key:
            raise APIKeyMissing
        url = f"https://api.socket.dev/v0/{path}"

    if headers is None:
        headers = {
            'Authorization': f"Basic {api_key}",
            'User-Agent': f'SocketPythonCLI/{__version__}',
            "accept": "application/json"
        }

    response = requests.request(
        method.upper(),
        url,
        headers=headers,
        data=payload,
        files=files,
        timeout=timeout,
        verify=verify_ssl
    )

    return response

# File pattern definitions
socket_globs = {
    "spdx": {
        "spdx.json": {
            "pattern": "*[-.]spdx.json"
        }
    },
    "cdx": {
        "cyclonedx.json": {
            "pattern": "{bom,*[-.]c{yclone,}dx}.json"
        },
        "xml": {
            "pattern": "{bom,*[-.]c{yclone,}dx}.xml"
        }
    },
    "npm": {
        "package.json": {
            "pattern": "package.json"
        },
        "package-lock.json": {
            "pattern": "package-lock.json"
        },
        "npm-shrinkwrap.json": {
            "pattern": "npm-shrinkwrap.json"
        },
        "yarn.lock": {
            "pattern": "yarn.lock"
        },
        "pnpm-lock.yaml": {
            "pattern": "pnpm-lock.yaml"
        },
        "pnpm-lock.yml": {
            "pattern": "pnpm-lock.yml"
        },
        "pnpm-workspace.yaml": {
            "pattern": "pnpm-workspace.yaml"
        },
        "pnpm-workspace.yml": {
            "pattern": "pnpm-workspace.yml"
        }
    },
    "pypi": {
        "pipfile": {
            "pattern": "pipfile"
        },
        "pyproject.toml": {
            "pattern": "pyproject.toml"
        },
        "poetry.lock": {
            "pattern": "poetry.lock"
        },
        "requirements.txt": {
            "pattern": "*requirements.txt"
        },
        "requirements": {
            "pattern": "requirements/*.txt"
        },
        "requirements-*.txt": {
            "pattern": "requirements-*.txt"
        },
        "requirements_*.txt": {
            "pattern": "requirements_*.txt"
        },
        "requirements.frozen": {
            "pattern": "requirements.frozen"
        },
        "setup.py": {
            "pattern": "setup.py"
        }
    },
    "golang": {
        "go.mod": {
            "pattern": "go.mod"
        },
        "go.sum": {
            "pattern": "go.sum"
        }
    },
    "java": {
        "pom.xml": {
            "pattern": "pom.xml"
        }
    }
}