#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys

INIT_FILE = pathlib.Path("socketsecurity/__init__.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")

VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*".*"$', re.MULTILINE)

def get_git_tag():
    try:
        tag = subprocess.check_output([
            "git", "describe", "--tags", "--exact-match"
        ], stderr=subprocess.DEVNULL, text=True).strip()
        return tag.lstrip("v")
    except subprocess.CalledProcessError:
        return None

def get_latest_tag():
    try:
        tag = subprocess.check_output([
            "git", "describe", "--tags", "--abbrev=0"
        ], text=True).strip()
        return tag.lstrip("v")
    except subprocess.CalledProcessError:
        return "0.0.0"

def get_commit_count_since(tag):
    try:
        output = subprocess.check_output([
            "git", "rev-list", f"v{tag}..HEAD", "--count"
        ], text=True).strip()
        return int(output)
    except subprocess.CalledProcessError:
        return 0

def inject_version(version: str):
    print(f"\U0001f501 Injecting version: {version}")

    # Update __init__.py
    init_content = INIT_FILE.read_text()
    new_init_content = VERSION_PATTERN.sub(f"__version__ = '{version}'", init_content)
    INIT_FILE.write_text(new_init_content)

    # Update pyproject.toml
    pyproject = PYPROJECT_FILE.read_text()
    if PYPROJECT_PATTERN.search(pyproject):
        new_pyproject = PYPROJECT_PATTERN.sub(f'version = "{version}"', pyproject)
    else:
        new_pyproject = re.sub(r"(\[project\])", rf"\1\nversion = \"{version}\"", pyproject)
    PYPROJECT_FILE.write_text(new_pyproject)

def main():
    dev_mode = "--dev" in sys.argv

    if dev_mode:
        base = get_latest_tag()
        commits = get_commit_count_since(base)
        version = f"{base}.dev{commits}"
    else:
        version = get_git_tag()
        if not version:
            print("\u274c Error: No exact tag found for release.")
            sys.exit(1)

    inject_version(version)
    print(f"\u2705 Injected {'dev' if dev_mode else 'release'} version: {version}")

if __name__ == "__main__":
    main()