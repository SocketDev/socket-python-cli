#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys

PACKAGE_FILE = pathlib.Path("socketsecurity/__init__.py")
VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")

def get_hatch_version():
    return subprocess.check_output(["hatch", "version"], text=True).strip()

def get_current_version():
    content = PACKAGE_FILE.read_text()
    match = VERSION_PATTERN.search(content)
    return match.group(1) if match else None

def update_version(new_version):
    content = PACKAGE_FILE.read_text()
    new_content = VERSION_PATTERN.sub(f"__version__ = '{new_version}'", content)
    PACKAGE_FILE.write_text(new_content)

def main():
    hatch_version = get_hatch_version()
    current_version = get_current_version()

    if not current_version:
        print("❌ Couldn't find __version__ in", PACKAGE_FILE)
        return 1

    if hatch_version != current_version:
        print(f"🔁 Syncing version: {current_version} → {hatch_version}")
        update_version(hatch_version)
        return 1  # Exit 1 so pre-commit fails and shows diff

    print(f"✅ Version is in sync: {hatch_version}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
