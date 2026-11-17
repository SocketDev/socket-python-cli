import importlib.util
import io
import json
import subprocess
from pathlib import Path

import pytest
from packaging.version import Version


@pytest.fixture
def version_check():
    script = Path(__file__).resolve().parents[2] / ".hooks" / "check_version.py"
    spec = importlib.util.spec_from_file_location("check_version", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def version_repo(tmp_path, monkeypatch, version_check):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "github-env"))
    monkeypatch.setattr(version_check, "latest_pypi_version", lambda: Version("2.12.0"))

    def git(*args):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def prepare(
        *,
        main_version="2.12.0",
        pr_version=None,
        project_version=None,
        changed_path="socketsecurity/scan.py",
        quote='"',
        tag=False,
    ):
        git("init", "-b", "main")
        git("config", "user.name", "Version check test")
        git("config", "user.email", "test@example.com")
        (tmp_path / "socketsecurity").mkdir()
        init_file = tmp_path / "socketsecurity" / "__init__.py"
        project_file = tmp_path / "pyproject.toml"
        init_file.write_text(f'__version__ = "{main_version}"\n')
        project_file.write_text(f'[project]\nversion = "{main_version}"\n')
        git("add", ".")
        git("commit", "-m", "Create release baseline")
        git("update-ref", "refs/remotes/origin/main", "HEAD")

        pr_version = pr_version or main_version
        init_file.write_text(f"__version__ = {quote}{pr_version}{quote}\n")
        project_file.write_text(f'[project]\nversion = "{project_version or pr_version}"\n')
        changed = tmp_path / changed_path
        changed.parent.mkdir(parents=True, exist_ok=True)
        content = changed.read_text() if changed.exists() else ""
        changed.write_text(content + "# Pull request content\n")
        git("add", ".")
        git("commit", "-m", "Update pull request files")
        if tag:
            git("tag", f"v{pr_version}")
        return version_check.main

    return prepare


@pytest.mark.parametrize(
    ("changed_path", "expected"),
    [
        ("README.md", 0),
        ("docs/cli-reference.md", 0),
        (".github/workflows/lint.yml", 0),
        (".hooks/check_version.py", 0),
        ("tests/unit/test_output.py", 0),
        ("socketsecurity/scan.py", 1),
        ("pyproject.toml", 1),
        ("uv.lock", 1),
    ],
)
def test_published_version_is_rejected_only_for_packaged_changes(version_repo, capsys, changed_path, expected):
    check = version_repo(changed_path=changed_path)
    assert check() == expected
    output = capsys.readouterr().out
    assert "already published on PyPI" in output
    assert ("Not enforced" in output) == (expected == 0)


def test_source_change_can_share_mains_unreleased_version(version_repo, capsys):
    check = version_repo(main_version="2.12.1")
    assert check() == 0
    assert "Riding main's unreleased 2.12.1" in capsys.readouterr().out


@pytest.mark.parametrize("quote", ['"', "'"])
def test_new_release_accepts_both_version_quote_styles(version_repo, tmp_path, capsys, quote):
    check = version_repo(pr_version="2.12.1", quote=quote)
    assert check() == 0
    assert "Version properly incremented" in capsys.readouterr().out
    assert (tmp_path / "github-env").read_text() == "PR_VERSION=2.12.1\nMAIN_VERSION=2.12.0\n"


def test_packaged_version_must_match_cli_version(version_repo, capsys):
    check = version_repo(pr_version="2.12.1", project_version="2.12.2")
    assert check() == 1
    assert "Version mismatch inside the PR" in capsys.readouterr().out


@pytest.mark.parametrize(("changed_path", "expected"), [("socketsecurity/scan.py", 1), ("README.md", 0)])
def test_existing_release_tag_respects_package_change_exemption(version_repo, capsys, changed_path, expected):
    check = version_repo(main_version="2.12.1", changed_path=changed_path, tag=True)
    assert check() == expected
    assert "Tag v2.12.1 already exists" in capsys.readouterr().out


def test_packaged_version_cannot_move_backwards(version_repo, capsys):
    check = version_repo(main_version="2.12.2", pr_version="2.12.1")
    assert check() == 1
    assert "Version moves backwards" in capsys.readouterr().out


def test_latest_pypi_version_ignores_prereleases_and_dev_releases(version_check, monkeypatch):
    payload = json.dumps({"releases": {"2.12.0": [], "2.11.9": [], "2.13.0rc1": [], "2.13.0.dev1": []}}).encode()
    monkeypatch.setattr(version_check.urllib.request, "urlopen", lambda _url: io.BytesIO(payload))
    assert version_check.latest_pypi_version() == Version("2.12.0")
