"""Test directory selection for manifest discovery."""
import sys
import types
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from socketsecurity import socketcli
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


@pytest.mark.parametrize(("flags", "include_node", "include_other"), [
    pytest.param([], False, False, id="default"),
    pytest.param(["--include-module-folders"], True, True, id="module-folders"),
    pytest.param(["--include-dirs", "node_modules,bower_components,jspm_packages"], True, True, id="include-dirs"),
    pytest.param(["--include-module-folders", "--exclude-paths", "node_modules"], False, True, id="exclude-paths"),
])
def test_cli_manifest_selection(tmp_path, monkeypatch, mocker, flags, include_node, include_other):
    root_files = {"package-lock.json", "installed.cdx.json"}
    node_files = {
        "node_modules/@scope/parent/package.json",
        "node_modules/@scope/parent/node_modules/child/yarn.lock",
        "node_modules/@scope/parent/requirements.txt",
    }
    other_modules = {"bower_components/pkg/package.json", "nested/jspm_packages/pkg/package.json"}
    excluded_files = {"node_modules/.package-lock.json", "vendor/requirements.txt", ".venv/requirements.txt"}
    for name in root_files | node_files | other_modules | excluded_files:
        manifest = tmp_path / name
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.touch()

    sdk = MagicMock()
    sdk.org.get.return_value = {"organizations": {"org-id": {"slug": "test-org", "plan": "enterprise"}}}
    sdk.report.supported.return_value = {
        "npm": {name: {"pattern": name} for name in ("package.json", "package-lock.json", "yarn.lock")},
        "pypi": {"requirements": {"pattern": "requirements.txt"}},
        "cdx": {"json": {"pattern": "{bom,c{yclone,}dx[-.]*,*[-.]c{yclone,}dx}.json"}},
    }
    mocker.patch.object(socketcli, "build_socket_sdk", return_value=sdk)
    mocker.patch.object(socketcli, "CliClient")
    mocker.patch.object(socketcli, "StreamingLogs", return_value=nullcontext(MagicMock()))
    mocker.patch.object(socketcli, "apply_git_context", return_value=(False, None))
    upload = mocker.patch.object(Core, "create_full_scan", return_value=types.SimpleNamespace(id="scan"))
    monkeypatch.setattr(sys, "argv", [
        "socketcli", *BASE_ARGS, "--branch", "main", "--target-path", str(tmp_path), *flags,
    ])

    with pytest.raises(SystemExit) as exit_status:
        socketcli.cli()

    assert exit_status.value.code == 0
    upload.assert_called_once()
    submitted = {Path(path).relative_to(tmp_path).as_posix() for path in upload.call_args.args[0]}
    expected = root_files.copy()
    if include_other:
        expected |= other_modules
    if include_node:
        expected |= node_files
    assert submitted == expected
