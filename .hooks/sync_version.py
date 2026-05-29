#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys
import urllib.request
import json

INIT_FILE = pathlib.Path("socketsecurity/__init__.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")
UV_LOCK_FILE = pathlib.Path("uv.lock")

VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*".*"$', re.MULTILINE)
STABLE_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
PYPI_PROD_API = "https://pypi.org/pypi/socketsecurity/json"
PYPI_TEST_API = "https://test.pypi.org/pypi/socketsecurity/json"

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

def bump_patch_version(version: str) -> str:
    if ".dev" in version:
        version = version.split(".dev")[0]
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)

def parse_stable_version(version: str):
    if not STABLE_VERSION_PATTERN.fullmatch(version):
        return None
    return tuple(int(part) for part in version.split("."))


def format_stable_version(version_parts) -> str:
    return ".".join(str(part) for part in version_parts)


def fetch_existing_versions(api_url: str) -> set:
    try:
        with urllib.request.urlopen(api_url) as response:
            data = json.load(response)
            return set(data.get("releases", {}).keys())
    except Exception as e:
        print(f"⚠️ Warning: Failed to fetch versions from {api_url}: {e}")
        return set()


def fetch_latest_stable_pypi_version():
    versions = fetch_existing_versions(PYPI_PROD_API)
    stable_versions = []
    for ver in versions:
        parsed = parse_stable_version(ver)
        if parsed is not None:
            stable_versions.append(parsed)
    if not stable_versions:
        return None
    return max(stable_versions)

def find_next_available_dev_version(base_version: str) -> str:
    existing_versions = fetch_existing_versions(PYPI_TEST_API)
    for i in range(1, 100):
        candidate = f"{base_version}.dev{i}"
        if candidate not in existing_versions:
            return candidate
    print("❌ Could not find available .devN slot after 100 attempts.")
    sys.exit(1)


def find_next_stable_patch_version(current_version: str) -> str:
    current_stable = current_version.split(".dev")[0] if ".dev" in current_version else current_version
    current_parts = parse_stable_version(current_stable)
    if current_parts is None:
        print(f"❌ Unsupported version format for stable bump: {current_version}")
        sys.exit(1)

    latest_pypi_parts = fetch_latest_stable_pypi_version()
    base_parts = max([current_parts, latest_pypi_parts] if latest_pypi_parts else [current_parts])
    next_parts = (base_parts[0], base_parts[1], base_parts[2] + 1)
    return format_stable_version(next_parts)

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


def run_uv_lock() -> bool:
    before = UV_LOCK_FILE.read_bytes() if UV_LOCK_FILE.exists() else b""
    try:
        subprocess.run(["uv", "lock"], check=True, text=True)
    except FileNotFoundError:
        print("❌ `uv` is required but was not found in PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("❌ `uv lock` failed. Please run it manually and fix any errors.")
        sys.exit(1)

    after = UV_LOCK_FILE.read_bytes() if UV_LOCK_FILE.exists() else b""
    return before != after

def main():
    dev_mode = "--dev" in sys.argv
    current_version = read_version_from_init(INIT_FILE)
    previous_version = read_version_from_git("socketsecurity/__init__.py")

    print(f"Current: {current_version}, Previous: {previous_version}")

    if current_version == previous_version:
        if dev_mode:
            base_version = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            new_version = find_next_available_dev_version(base_version)
            inject_version(new_version)
            uv_lock_changed = run_uv_lock()
            lock_hint = " and uv.lock" if uv_lock_changed else ""
            print(f"⚠️ Version was unchanged — auto-bumped. Please git add{lock_hint} + commit again.")
            sys.exit(0)
        else:
            new_version = find_next_stable_patch_version(current_version)
            inject_version(new_version)
            uv_lock_changed = run_uv_lock()
            lock_hint = " and uv.lock" if uv_lock_changed else ""
            print(f"⚠️ Version was unchanged — auto-bumped to {new_version}. Please git add{lock_hint} + commit again.")
            sys.exit(1)
    else:
        if not dev_mode:
            current_parts = parse_stable_version(current_version)
            latest_pypi_parts = fetch_latest_stable_pypi_version()
            if current_parts is not None and latest_pypi_parts is not None and current_parts <= latest_pypi_parts:
                next_parts = (latest_pypi_parts[0], latest_pypi_parts[1], latest_pypi_parts[2] + 1)
                new_version = format_stable_version(next_parts)
                inject_version(new_version)
                uv_lock_changed = run_uv_lock()
                lock_hint = " and uv.lock" if uv_lock_changed else ""
                print(f"⚠️ Version {current_version} is already published on PyPI — auto-bumped to {new_version}. Please git add{lock_hint} + commit again.")
                sys.exit(1)

        uv_lock_changed = run_uv_lock()
        if uv_lock_changed:
            print("⚠️ Version already bumped, but uv.lock was out of date and has been updated. Please git add uv.lock + commit again.")
            sys.exit(1)

        print("✅ Version already bumped and uv.lock is up to date — proceeding.")
        sys.exit(0)

if __name__ == "__main__":
    main()
