#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys

INIT_FILE = pathlib.Path("socketsecurity/__init__.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")

VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*".*"$', re.MULTILINE)

def read_version_from_init(path: pathlib.Path) -> str:
    content = path.read_text()
    match = VERSION_PATTERN.search(content)
    if not match:
        print(f"❌ Could not find __version__ in {path}")
        sys.exit(1)
    return match.group(1)

def read_version_from_git(path: str) -> str:
    try:
        output = subprocess.check_output(["git", "show", f"HEAD:{path}"], text=True)
        match = VERSION_PATTERN.search(output)
        if not match:
            return None
        return match.group(1)
    except subprocess.CalledProcessError:
        return None

def bump_dev_version(version: str) -> str:
    if ".dev" in version:
        base, dev = version.split(".dev")
        return f"{base}.dev{int(dev)+1}"
    else:
        return f"{version}.dev1"

def inject_version(version: str):
    print(f"🔁 Updating version to: {version}")

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
    current_version = read_version_from_init(INIT_FILE)
    previous_version = read_version_from_git("socketsecurity/__init__.py")

    print(f"Current: {current_version}, Previous: {previous_version}")

    if current_version == previous_version:
        new_version = bump_dev_version(current_version)
        inject_version(new_version)
        print("⚠️ Version was unchanged — auto-bumped. Please git add + commit again.")
        sys.exit(1)
    else:
        print("✅ Version already bumped — proceeding.")
        sys.exit(0)

if __name__ == "__main__":
    main()
