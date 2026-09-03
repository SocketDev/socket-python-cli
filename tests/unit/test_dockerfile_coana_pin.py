"""Guards the image's ``@coana-tech/cli`` install against drifting from the runtime pin.

The launcher asks npx for ``@coana-tech/cli@DEFAULT_COANA_CLI_VERSION``, and npx reuses the
image's global install only when the versions match; on a mismatch it downloads the engine
again on every scan. The Dockerfile therefore derives the version from ``reachability.py``
with a ``sed`` expression instead of repeating it. These tests run that expression against
the real source, so a reformatted constant or a broken expression fails here rather than
silently producing a mismatched image.
"""

import re
import subprocess
from pathlib import Path

from socketsecurity.core.tools.reachability import DEFAULT_COANA_CLI_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
REACHABILITY_SOURCE = (
    REPO_ROOT / "socketsecurity" / "core" / "tools" / "reachability.py"
)


def _dockerfile_sed_expression() -> str:
    """Return the pin-extraction expression the Dockerfile runs."""
    match = re.search(
        r"sed -n '(s/\^DEFAULT_COANA_CLI_VERSION[^']*)'", DOCKERFILE.read_text()
    )
    assert match, "Dockerfile no longer extracts DEFAULT_COANA_CLI_VERSION with sed"
    return match.group(1)


def test_dockerfile_expression_extracts_the_pinned_version():
    extracted = subprocess.run(
        ["sed", "-n", _dockerfile_sed_expression(), str(REACHABILITY_SOURCE)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert extracted == DEFAULT_COANA_CLI_VERSION


def test_dockerfile_never_installs_coana_unpinned():
    install_lines = [
        line for line in DOCKERFILE.read_text().splitlines() if "npm install" in line
    ]
    assert install_lines, "Dockerfile no longer installs anything with npm"
    for line in install_lines:
        if "@coana-tech/cli" in line:
            assert "@coana-tech/cli@" in line, f"unpinned coana install: {line.strip()}"
