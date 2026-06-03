"""Tests for the unified --exclude-paths flag (G2, Node alignment).

Covers the path matcher, config parsing + soft-deprecation of --reach-exclude-paths,
and that --exclude-paths filters SCA manifest discovery via Core.find_files.
"""
import logging
import types
from unittest.mock import MagicMock

import pytest

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig

# ---- matcher -------------------------------------------------------------

@pytest.mark.parametrize(
    "rel, patterns, expected",
    [
        # directory prefix -> the directory's whole subtree
        ("packages/legacy/package.json", ["packages/legacy"], True),
        ("packages/keep/package.json", ["packages/legacy"], False),
        # root-anchored: a bare name matches at the root only, NOT nested
        ("tests/x.json", ["tests"], True),
        ("src/tests/x.json", ["tests"], False),
        # **/ matches at any depth
        ("src/tests/x.json", ["**/tests"], True),
        ("tests/unit/x.json", ["tests/**"], True),
        ("tests", ["tests/**"], False),                # P/** is the subtree, not P itself
        # '*' does NOT cross '/': anchored basename glob is root-level only
        ("index.spec.ts", ["*.spec.ts"], True),
        ("src/app/index.spec.ts", ["*.spec.ts"], False),
        ("src/app/index.spec.ts", ["**/*.spec.ts"], True),
        ("src/app/index.ts", ["**/*.spec.ts"], False),
        # single-star matches exactly one path segment
        ("packages/a/node_modules/x.json", ["packages/*/node_modules"], True),
        ("packages/a/b/node_modules/x.json", ["packages/*/node_modules"], False),
    ],
)
def test_matches_exclude_paths(rel, patterns, expected):
    assert Core.matches_exclude_paths(rel, ".", patterns) is expected


@pytest.mark.parametrize(
    "pattern, excluded, kept",
    [
        # Node parity cases (src/commands/scan/exclude-paths.mts), anchored at scan root.
        ("tests", "tests/pkg/package.json", "src/tests/package.json"),
        ("package-lock.json", "package-lock.json", "packages/a/package-lock.json"),
        ("**/node_modules", "packages/a/node_modules/dep/package.json", "src/app/package.json"),
        ("packages/legacy", "packages/legacy/p.json", "packages/legacy-x/p.json"),
        ("src/*.json", "src/a.json", "src/sub/a.json"),
    ],
)
def test_matches_exclude_paths_node_parity(pattern, excluded, kept):
    assert Core.matches_exclude_paths(excluded, ".", [pattern]) is True
    assert Core.matches_exclude_paths(kept, ".", [pattern]) is False


def test_matches_exclude_paths_empty_is_false():
    assert Core.matches_exclude_paths("a/b.json", ".", []) is False
    assert Core.matches_exclude_paths("a/b.json", ".", ["  "]) is False


# ---- config parsing ------------------------------------------------------

BASE_ARGS = ["--api-token", "test-token", "--repo", "test-repo"]


def test_exclude_paths_parses_to_list():
    config = CliConfig.from_args(BASE_ARGS + ["--exclude-paths", "tests/**, packages/legacy , *.spec.ts"])
    assert config.exclude_paths == ["tests/**", "packages/legacy", "*.spec.ts"]


def test_exclude_paths_defaults_none():
    config = CliConfig.from_args(BASE_ARGS)
    assert config.exclude_paths is None


def test_reach_exclude_paths_still_works_and_warns(caplog):
    with caplog.at_level(logging.WARNING):
        config = CliConfig.from_args(BASE_ARGS + ["--reach", "--reach-exclude-paths", "a,b"])
    assert config.reach_exclude_paths == ["a", "b"]
    assert any("deprecated" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    "bad",
    ["!foo", "/abs/path", "..", "../escape", "a/../b", ".", "**", "**/", "/**", "./", "./**"],
)
def test_exclude_paths_validation_rejects(bad):
    with pytest.raises(SystemExit) as exc:
        CliConfig.from_args(BASE_ARGS + ["--exclude-paths", bad])
    assert exc.value.code == 1


def test_exclude_paths_validation_rejects_within_csv():
    with pytest.raises(SystemExit) as exc:
        CliConfig.from_args(BASE_ARGS + ["--exclude-paths", "src,..,tests"])
    assert exc.value.code == 1


def _write_config(tmp_path, value):
    import json
    path = tmp_path / "socketcli.json"
    path.write_text(json.dumps({"socketcli": {"exclude_paths": value}}), encoding="utf-8")
    return str(path)


def test_exclude_paths_from_config_file_list(tmp_path):
    """A JSON list in --config flows through normalization (not just CSV strings)."""
    cfg = _write_config(tmp_path, ["tests/**", "packages/legacy"])
    config = CliConfig.from_args(BASE_ARGS + ["--config", cfg])
    assert config.exclude_paths == ["tests/**", "packages/legacy"]


def test_exclude_paths_from_config_file_string(tmp_path):
    cfg = _write_config(tmp_path, "tests/**, packages/legacy")
    config = CliConfig.from_args(BASE_ARGS + ["--config", cfg])
    assert config.exclude_paths == ["tests/**", "packages/legacy"]


def test_exclude_paths_from_config_file_is_validated(tmp_path):
    """Config-file patterns are validated too (not bypassed)."""
    cfg = _write_config(tmp_path, ["../escape"])
    with pytest.raises(SystemExit) as exc:
        CliConfig.from_args(BASE_ARGS + ["--config", cfg])
    assert exc.value.code == 1


def test_exclude_paths_valid_globs_accepted():
    config = CliConfig.from_args(BASE_ARGS + ["--exclude-paths", "tests/**,**/*.spec.ts,packages/legacy"])
    assert config.exclude_paths == ["tests/**", "**/*.spec.ts", "packages/legacy"]


# ---- find_files integration ---------------------------------------------

def _make_core(exclude_paths):
    core = Core.__new__(Core)
    core.config = SocketConfig(api_key="test-key")
    core.cli_config = types.SimpleNamespace(exclude_paths=exclude_paths)
    core.sdk = MagicMock()
    return core


def _seed_manifests(tmp_path):
    for rel in ("package.json", "sub/package.json", "legacy/package.json"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}", encoding="utf-8")


def test_find_files_excludes_matching_paths(tmp_path, mocker):
    _seed_manifests(tmp_path)
    core = _make_core(["legacy"])
    mocker.patch.object(
        core, "get_supported_patterns",
        return_value={"npm": {"package.json": {"pattern": "package.json"}}},
    )

    found = core.find_files(str(tmp_path))
    assert any(f.endswith("/package.json") and "/legacy/" not in f for f in found)
    assert not any("/legacy/" in f for f in found)


def test_find_files_no_exclude_paths_keeps_all(tmp_path, mocker):
    _seed_manifests(tmp_path)
    core = _make_core(None)
    mocker.patch.object(
        core, "get_supported_patterns",
        return_value={"npm": {"package.json": {"pattern": "package.json"}}},
    )

    found = core.find_files(str(tmp_path))
    assert any("/legacy/" in f for f in found)
    assert len(found) == 3
