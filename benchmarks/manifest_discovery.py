#!/usr/bin/env python3
"""Compare legacy per-pattern rglob discovery with the single-pass walker.

This is an opt-in developer benchmark, not a timing assertion in the test
suite. It creates a synthetic monorepo so filesystem or CI-agent changes do not
make regular tests flaky.
"""

import argparse
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.core.utils import socket_globs


def seed_tree(root: Path, directories: int, files_per_directory: int) -> None:
    for directory_index in range(directories):
        directory = root / "packages" / f"package-{directory_index:05d}"
        directory.mkdir(parents=True)
        (directory / "package.json").write_text("{}\n", encoding="utf-8")
        for file_index in range(files_per_directory):
            (directory / f"source-{file_index:03d}.txt").write_text(
                "not a manifest\n",
                encoding="utf-8",
            )

    # These trees model the expensive directories that the new walker prunes
    # before descent rather than visiting once for every manifest pattern.
    for excluded in (".git/objects", "node_modules/example", ".venv/site-packages"):
        directory = root / excluded
        directory.mkdir(parents=True)
        for index in range(files_per_directory * 10):
            (directory / f"object-{index:05d}").write_text("x", encoding="utf-8")


def legacy_discover(root: Path) -> set[str]:
    results = set()
    excluded_dirs = SocketConfig(api_key="benchmark").excluded_dirs
    for ecosystem_patterns in socket_globs.values():
        for details in ecosystem_patterns.values():
            for pattern in Core.expand_brace_pattern(details["pattern"]):
                insensitive = Core.to_case_insensitive_regex(pattern)
                for candidate in root.rglob(insensitive):
                    if candidate.is_file() and not Core.is_excluded(
                            str(candidate),
                            excluded_dirs,
                    ):
                        results.add(candidate.as_posix())
    return results


def new_core() -> Core:
    core = Core.__new__(Core)
    core.config = SocketConfig(api_key="benchmark")
    core.cli_config = SimpleNamespace(exclude_paths=None)
    core.sdk = MagicMock()
    core._supported_patterns = socket_globs
    return core


def timed(function, root: Path) -> tuple[set[str], float]:
    start = time.perf_counter()
    results = set(function(root))
    return results, time.perf_counter() - start


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directories", type=int, default=500)
    parser.add_argument("--files-per-directory", type=int, default=20)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="socket-manifest-benchmark-") as temp:
        root = Path(temp)
        seed_tree(root, args.directories, args.files_per_directory)
        legacy_results, legacy_seconds = timed(legacy_discover, root)
        new_results, new_seconds = timed(
            lambda path: new_core().find_files(str(path)),
            root,
        )

    if legacy_results != new_results:
        raise SystemExit(
            "Manifest result mismatch: "
            f"legacy={len(legacy_results)}, single_pass={len(new_results)}"
        )

    speedup = legacy_seconds / new_seconds if new_seconds else float("inf")
    print(f"Manifests: {len(new_results)}")
    print(f"Legacy per-pattern rglob: {legacy_seconds:.3f}s")
    print(f"Single-pass walk: {new_seconds:.3f}s")
    print(f"Speedup: {speedup:.1f}x")


if __name__ == "__main__":
    main()
