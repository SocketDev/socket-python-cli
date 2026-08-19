import logging
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig, default_exclude_dirs
from socketsecurity.core.utils import socket_globs


def _make_core(*, patterns=socket_globs, excluded_dirs=None, exclude_paths=None):
    core = Core.__new__(Core)
    core.config = SocketConfig(
        api_key="test-key",
        excluded_dirs=set(default_exclude_dirs if excluded_dirs is None else excluded_dirs),
    )
    core.cli_config = SimpleNamespace(exclude_paths=exclude_paths)
    core.sdk = MagicMock()
    core._supported_patterns = patterns
    return core


def _write_files(root: Path, relative_paths):
    for relative_path in relative_paths:
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("test\n", encoding="utf-8")


def _relative_results(root: Path, results):
    return {Path(result).relative_to(root).as_posix() for result in results}


ALL_PATTERN_EXAMPLES = {
    "app.spdx.json",
    "bom.json",
    "nested/app-cdx.json",
    "nested/app-cyclonedx.xml",
    "package.json",
    "nested/package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "pnpm-workspace.yaml",
    "pnpm-workspace.yml",
    "bun.lock",
    "bun.lockb",
    "vlt-lock.json",
    "PIPFILE",
    "pyproject.toml",
    "poetry.lock",
    "requirements.txt",
    "dev-requirements.txt",
    "requirements-dev.txt",
    "requirements_test.txt",
    "requirements.frozen",
    "requirements/base.txt",
    "nested/requirements/constraints.txt",
    "setup.py",
    "go.mod",
    "go.sum",
    "pom.xml",
    "src/Project.CSPROJ",
    "Directory.Build.Props",
    "build.targets",
    "project.nuspec",
    "nuget.CONFIG",
    "packages.config",
    "packages.lock.json",
}


def test_all_builtin_manifest_patterns_match_in_one_walk(tmp_path, mocker):
    _write_files(
        tmp_path,
        ALL_PATTERN_EXAMPLES
        | {
            "README.md",
            "requirements/deep/not-a-direct-child.txt",
            "src/package.json.backup",
        },
    )
    original_walk = os.walk
    walk = mocker.patch("socketsecurity.core.os.walk", wraps=original_walk)

    found = _relative_results(tmp_path, _make_core().find_files(str(tmp_path)))

    assert found == ALL_PATTERN_EXAMPLES
    walk.assert_called_once()


def test_single_walk_matches_legacy_rglob_results_for_builtin_patterns(tmp_path):
    _write_files(
        tmp_path,
        ALL_PATTERN_EXAMPLES
        | {
            ".hidden/package.json",
            "nested/Requirements.TXT",
            "src/not-a-manifest.json",
        },
    )
    core = _make_core(excluded_dirs=set())

    legacy_results = set()
    for ecosystem_patterns in socket_globs.values():
        for details in ecosystem_patterns.values():
            for expanded in Core.expand_brace_pattern(details["pattern"]):
                case_insensitive = Core.to_case_insensitive_regex(expanded)
                for result in tmp_path.rglob(case_insensitive):
                    if result.is_file():
                        legacy_results.add(result.as_posix())

    assert set(core.find_files(str(tmp_path))) == legacy_results


def test_directory_only_pattern_does_not_match_same_named_file(tmp_path):
    """A trailing slash keeps pathlib.rglob's directory-only semantics."""
    _write_files(
        tmp_path,
        {
            "manifests/package.json",
            "nested/manifests",
        },
    )
    patterns = {
        "test": {
            "directory-only": {"pattern": "manifests/"},
        },
    }

    assert _make_core(patterns=patterns).find_files(str(tmp_path)) == []


def test_prunes_git_default_globs_and_exclude_paths_before_descent(
        tmp_path, mocker, caplog
):
    _write_files(
        tmp_path,
        {
            "package.json",
            ".git/objects/package.json",
            "node_modules/pkg/package.json",
            "generated.egg-info/package.json",
            "legacy/nested/package.json",
            ".hidden/package.json",
        },
    )
    scanned_directories = []
    original_scandir = os.scandir

    def tracking_scandir(path):
        scanned_directories.append(Path(path).relative_to(tmp_path).as_posix())
        return original_scandir(path)

    mocker.patch("socketsecurity.core.os.scandir", side_effect=tracking_scandir)
    core = _make_core(exclude_paths=["legacy"])

    with caplog.at_level(logging.INFO, logger="socketdev"):
        found = _relative_results(tmp_path, core.find_files(str(tmp_path)))

    assert found == {"package.json", ".hidden/package.json"}
    assert ".git" not in scanned_directories
    assert "node_modules" not in scanned_directories
    assert "generated.egg-info" not in scanned_directories
    assert "legacy" not in scanned_directories
    assert any(
        "directories_pruned=4" in record.message
        and "manifests_found=2" in record.message
        for record in caplog.records
    )


def test_include_dirs_and_excluded_ecosystems_are_preserved(tmp_path):
    _write_files(
        tmp_path,
        {
            "build/package.json",
            "build/requirements.txt",
            "dist/package.json",
        },
    )
    core = _make_core(excluded_dirs=set(default_exclude_dirs) - {"build"})
    core.config.excluded_ecosystems = ["npm"]

    found = _relative_results(tmp_path, core.find_files(str(tmp_path)))

    assert found == {"build/requirements.txt"}


def test_excluding_every_ecosystem_skips_the_filesystem_walk(tmp_path, mocker):
    core = _make_core()
    core.config.excluded_ecosystems = list(socket_globs)
    walk = mocker.patch(
        "socketsecurity.core.os.walk",
        side_effect=AssertionError("unexpected walk"),
    )

    assert core.find_files(str(tmp_path)) == []
    walk.assert_not_called()


def test_symlinked_file_is_included_but_symlinked_directory_is_not_followed(tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks are not supported")

    source_file = tmp_path / "source.txt"
    source_file.write_text("{}", encoding="utf-8")
    source_directory = tmp_path / "external"
    _write_files(source_directory, {"package.json"})
    try:
        (tmp_path / "package.json").symlink_to(source_file)
        (tmp_path / "linked-directory").symlink_to(source_directory, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable: {error}")

    found = _relative_results(tmp_path, _make_core().find_files(str(tmp_path)))

    assert "package.json" in found
    assert "linked-directory/package.json" not in found
    assert "external/package.json" in found


def test_supported_patterns_are_cached_without_mutating_sdk_response():
    response = {
        "general": {"ignored": {"pattern": "ignored"}},
        "npm": {"package.json": {"pattern": "package.json"}},
    }
    core = _make_core(patterns=None)
    core.sdk.report.supported.return_value = response

    first = core.get_supported_patterns()
    second = core.get_supported_patterns()

    assert first is second
    assert first == {"npm": {"package.json": {"pattern": "package.json"}}}
    assert "general" in response
    core.sdk.report.supported.assert_called_once_with()


def test_failed_pattern_lookup_is_not_cached():
    """A transient API failure must not pin the run to the smaller local fallback."""
    api_response = {"npm": {"package.json": {"pattern": "package.json"}}}
    core = _make_core(patterns=None)
    core.sdk.report.supported.side_effect = [None, api_response]

    fallback = core.get_supported_patterns()
    assert set(fallback) == set(socket_globs)

    recovered = core.get_supported_patterns()
    assert set(recovered) == {"npm"}
    # The successful lookup is still cached, so the API is not re-queried again.
    assert core.get_supported_patterns() is recovered
    assert core.sdk.report.supported.call_count == 2


def test_basename_prefilter_admits_every_supported_manifest():
    """The cheap prefilter must never reject a path the authoritative matcher accepts."""
    patterns = Core._prepare_manifest_patterns(socket_globs, None, [])

    for relative_path in ALL_PATTERN_EXAMPLES:
        basename = relative_path.rsplit("/", 1)[-1].casefold()
        assert Core._matches_manifest_pattern(relative_path, patterns), relative_path
        assert Core._basename_could_match(basename, patterns), relative_path


def test_results_are_sorted_and_deduplicated_across_overlapping_patterns(tmp_path):
    _write_files(tmp_path, {"z/package.json", "a/package.json"})
    overlapping_patterns = {
        "npm": {
            "literal": {"pattern": "package.json"},
            "wildcard": {"pattern": "package*.json"},
        }
    }

    found = _make_core(patterns=overlapping_patterns).find_files(str(tmp_path))

    assert found == sorted(found)
    assert len(found) == 2


def test_explicit_discovery_results_prevent_a_second_walk(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")
    core = _make_core()
    core.config.org_slug = "example"
    core.cli_config = None
    core.find_files = MagicMock(side_effect=AssertionError("unexpected second walk"))
    core.create_full_scan = MagicMock(return_value=SimpleNamespace(id="scan-123"))
    params = MagicMock()

    diff = core.create_full_scan_with_report_url(
        [str(tmp_path)],
        params,
        explicit_files=[manifest.as_posix()],
    )

    core.find_files.assert_not_called()
    core.create_full_scan.assert_called_once_with(
        [manifest.as_posix()],
        params,
        base_paths=None,
    )
    assert diff.id == "scan-123"


def test_core_initialization_logs_organization_timing(caplog):
    sdk = MagicMock()
    sdk.org.get.return_value = {
        "organizations": {"org-id": {"slug": "example"}},
    }

    with caplog.at_level(logging.INFO, logger="socketdev"):
        core = Core(SocketConfig(api_key="test-key"), sdk)

    assert core.config.org_slug == "example"
    assert any(
        "Organization initialization completed" in record.message
        for record in caplog.records
    )


def test_discovery_does_not_build_a_repository_sized_index(tmp_path):
    """Peak memory must stay bounded by the widest directory and the result set, not
    by repository size. This is the property that keeps discovery viable on small
    runners; the per-pattern rglob approach it replaced allocated strictly more.
    """
    import tracemalloc

    wide_directory = tmp_path / "wide"
    wide_directory.mkdir()
    for index in range(20000):
        (wide_directory / f"source{index:05d}.ts").write_text("x", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    core = _make_core()
    tracemalloc.start()
    try:
        found = core.find_files(str(tmp_path))
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert _relative_results(tmp_path, found) == {"package.json"}
    # 20k files in one directory; a repo-sized index would be far larger than this.
    assert peak_bytes < 8_000_000, f"peak allocation was {peak_bytes / 1e6:.1f} MB"
