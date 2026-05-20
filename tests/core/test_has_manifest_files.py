from unittest.mock import patch

from socketsecurity.core import Core
from socketsecurity.core.utils import socket_globs

# Minimal patterns matching what the Socket API returns
MOCK_PATTERNS = {
    "npm": {
        "packagejson": {"pattern": "package.json"},
        "packagelockjson": {"pattern": "package-lock.json"},
        "yarnlock": {"pattern": "yarn.lock"},
        "bunlock": {"pattern": "bun.lock"},
        "bunlockb": {"pattern": "bun.lockb"},
        "vltlockjson": {"pattern": "vlt-lock.json"},
    },
    "pypi": {
        "requirements": {"pattern": "*requirements.txt"},
        "requirementsin": {"pattern": "*requirements*.txt"},
        "setuppy": {"pattern": "setup.py"},
    },
    "maven": {
        "pomxml": {"pattern": "pom.xml"},
    },
}


@patch.object(Core, "get_supported_patterns", return_value=MOCK_PATTERNS)
@patch.object(Core, "__init__", lambda self, *a, **kw: None)
class TestHasManifestFiles:
    def test_root_level_package_json(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["package.json"]) is True

    def test_root_level_package_lock_json(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["package-lock.json"]) is True

    def test_subdirectory_package_json(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["libs/ui/package.json"]) is True

    def test_root_level_requirements_txt(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["requirements.txt"]) is True

    def test_subdirectory_requirements_txt(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["src/requirements.txt"]) is True

    def test_prefixed_requirements_txt(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["dev-requirements.txt"]) is True

    def test_no_manifest_files(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["README.md", "src/app.py"]) is False

    def test_mixed_files_with_manifest(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files([".gitlab-ci.yml", "package.json", "src/app.tsx"]) is True

    def test_empty_list(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files([]) is False

    def test_dot_slash_prefix_normalized(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["./package.json"]) is True

    def test_pom_xml_root(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["pom.xml"]) is True

    def test_bun_lock_root(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["bun.lock"]) is True

    def test_bun_lockb_root(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["bun.lockb"]) is True

    def test_vlt_lock_json_root(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["vlt-lock.json"]) is True

    def test_bun_lock_subdirectory(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["apps/web/bun.lock"]) is True


@patch.object(Core, "get_supported_patterns", side_effect=RuntimeError("API unreachable"))
@patch.object(Core, "__init__", lambda self, *a, **kw: None)
class TestHasManifestFilesFallback:
    """Exercises the socket_globs fallback path used when the Socket API is unreachable."""

    def test_fallback_matches_bun_lock(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["bun.lock"]) is True

    def test_fallback_matches_bun_lockb(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["bun.lockb"]) is True

    def test_fallback_matches_vlt_lock_json(self, mock_patterns):
        core = Core.__new__(Core)
        assert core.has_manifest_files(["vlt-lock.json"]) is True

    def test_fallback_patterns_dict_contains_new_entries(self, mock_patterns):
        assert "bun.lock" in socket_globs["npm"]
        assert "bun.lockb" in socket_globs["npm"]
        assert "vlt-lock.json" in socket_globs["npm"]
