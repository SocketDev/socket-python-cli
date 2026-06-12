"""Tests for --include-dirs (and the now-functional --include-module-folders).

Covers config parsing of the comma-separated directory names and that re-including a
normally-excluded directory (e.g. build) lets Core.find_files discover manifests under it.
"""
import types
from unittest.mock import MagicMock

import pytest

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.socket_config import (
    SocketConfig,
    default_exclude_dirs,
    module_folder_dirs,
)

BASE_ARGS = ["--api-token", "test-token", "--repo", "test-repo"]


# ---- config parsing ------------------------------------------------------

def test_include_dirs_parses_to_list():
    config = CliConfig.from_args(BASE_ARGS + ["--include-dirs", "build, dist , vendor"])
    assert config.included_dirs == ["build", "dist", "vendor"]


def test_include_dirs_defaults_empty():
    config = CliConfig.from_args(BASE_ARGS)
    assert config.included_dirs == []


def test_include_dirs_from_config_file(tmp_path):
    import json
    cfg = tmp_path / "socketcli.json"
    cfg.write_text(json.dumps({"socketcli": {"include_dirs": ["build", "dist"]}}), encoding="utf-8")
    config = CliConfig.from_args(BASE_ARGS + ["--config", str(cfg)])
    assert config.included_dirs == ["build", "dist"]


def test_module_folder_dirs_is_subset_of_defaults():
    assert module_folder_dirs <= default_exclude_dirs


# ---- find_files integration ----------------------------------------------

def _make_core(excluded_dirs):
    core = Core.__new__(Core)
    core.config = SocketConfig(api_key="test-key", excluded_dirs=excluded_dirs)
    core.cli_config = types.SimpleNamespace(exclude_paths=None)
    core.sdk = MagicMock()
    return core


def _seed_manifests(tmp_path):
    for rel in ("requirements.txt", "build/requirements.txt", "dist/requirements.txt"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("flask==1.0\n", encoding="utf-8")


def test_find_files_excludes_build_by_default(tmp_path, mocker):
    _seed_manifests(tmp_path)
    core = _make_core(set(default_exclude_dirs))
    mocker.patch.object(
        core, "get_supported_patterns",
        return_value={"pypi": {"requirements.txt": {"pattern": "requirements.txt"}}},
    )

    found = core.find_files(str(tmp_path))
    assert not any("/build/" in f for f in found)
    assert not any("/dist/" in f for f in found)
    assert any(f.endswith("/requirements.txt") for f in found)


def test_find_files_includes_build_when_unexcluded(tmp_path, mocker):
    """Mirrors socketcli wiring: dropping a name from excluded_dirs re-includes its manifests."""
    _seed_manifests(tmp_path)
    core = _make_core(set(default_exclude_dirs) - {"build"})
    mocker.patch.object(
        core, "get_supported_patterns",
        return_value={"pypi": {"requirements.txt": {"pattern": "requirements.txt"}}},
    )

    found = core.find_files(str(tmp_path))
    assert any("/build/requirements.txt" in f for f in found)
    # dist is still excluded since only build was re-included
    assert not any("/dist/" in f for f in found)


def test_unexcluding_does_not_mutate_shared_defaults():
    """The socketcli flow builds a new set rather than mutating the module-level default."""
    before = set(default_exclude_dirs)
    config = SocketConfig(api_key="test-key")
    config.excluded_dirs = set(config.excluded_dirs) - {"build"}
    assert "build" not in config.excluded_dirs
    assert default_exclude_dirs == before
    assert "build" in default_exclude_dirs
