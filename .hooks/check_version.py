"""Validate release versions for pull requests that change packaged files."""

import json
import os
import re
import subprocess
import tomllib
import urllib.request
from pathlib import Path

from packaging.version import Version


def read_version(source: str) -> Version:
    match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", source, re.MULTILINE)
    if not match:
        raise ValueError("No __version__ declaration found")
    return Version(match.group(1))


def latest_pypi_version() -> Version:
    with urllib.request.urlopen("https://pypi.org/pypi/socketsecurity/json") as response:
        releases = json.load(response).get("releases", {})
    versions = (Version(raw) for raw in releases)
    return max((v for v in versions if not v.is_prerelease and not v.is_devrelease), default=Version("0.0.0"))


def main() -> int:
    pr_ver = read_version(Path("socketsecurity/__init__.py").read_text())
    main_ver = read_version(
        subprocess.check_output(["git", "show", "origin/main:socketsecurity/__init__.py"], text=True)
    )
    changed_paths = subprocess.check_output(
        ["git", "diff", "--name-only", "origin/main...HEAD"], text=True
    ).splitlines()
    enforced = any(
        name.startswith("socketsecurity/") or name in {"pyproject.toml", "uv.lock"} for name in changed_paths
    )

    if github_env := os.environ.get("GITHUB_ENV"):
        with open(github_env, "a", encoding="utf-8") as env_file:
            env_file.write(f"PR_VERSION={pr_ver}\nMAIN_VERSION={main_ver}\n")

    def reject(message: str) -> int:
        print(message)
        if enforced:
            return 1
        print("ℹ️  Not enforced: this PR changes no packaged files, so it ships nothing that needs a new version.")
        return 0

    with open("pyproject.toml", "rb") as project_file:
        pyproject_ver = Version(tomllib.load(project_file)["project"]["version"])
    if pr_ver != pyproject_ver:
        return reject(
            f"❌ Version mismatch inside the PR: pyproject.toml is {pyproject_ver}, "
            f"socketsecurity/__init__.py is {pr_ver}. Bump both."
        )

    pypi_ver = latest_pypi_version()
    if pr_ver <= pypi_ver:
        return reject(f"❌ Version {pr_ver} is already published on PyPI (latest release: {pypi_ver}). Bump it.")

    # Published release tags are immutable, even if publication to PyPI fails.
    tag = f"v{pr_ver}"
    if (
        subprocess.run(
            ["git", "rev-parse", "--quiet", "--verify", f"refs/tags/{tag}"], capture_output=True, check=False
        ).returncode
        == 0
    ):
        return reject(
            f"❌ Tag {tag} already exists, so {pr_ver} can never be released "
            f"(latest PyPI release: {pypi_ver}). Bump to a version with no tag."
        )

    if pr_ver < main_ver:
        return reject(f"❌ Version moves backwards: main is {main_ver}, PR is {pr_ver}.")

    # Multiple pull requests may share main's unreleased version.
    if pr_ver == main_ver:
        print(f"✅ Riding main's unreleased {pr_ver} (latest PyPI release: {pypi_ver}).")
    else:
        print(f"✅ Version properly incremented. Main: {main_ver}, PyPI: {pypi_ver}, PR: {pr_ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
