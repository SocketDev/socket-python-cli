from pathlib import PurePath
from unittest.mock import patch

from socketsecurity.core import Core


# Minimal patterns matching what the Socket API returns
MOCK_PATTERNS = {
    "npm": {
        "packagejson": {"pattern": "package.json"},
        "packagelockjson": {"pattern": "package-lock.json"},
        "yarnlock": {"pattern": "yarn.lock"},
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
