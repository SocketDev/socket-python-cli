import re

import pytest
from socketsecurity.core.messages import Messages
from socketsecurity.core.classes import Diff, Issue


class TestGitLabFormat:
    """Test suite for GitLab Security Dashboard format generation"""

    # GitLab v15.0.0 schema: ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$
    GITLAB_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")

    def test_gitlab_report_structure(self):
        """Test basic GitLab report structure matches v15.0.0 schema requirements"""
        diff = Diff()
        diff.new_alerts = []
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        report = Messages.create_security_comment_gitlab(diff)

        # All four root-level keys required by v15.0.0 schema
        assert "version" in report
        assert "scan" in report
        assert "vulnerabilities" in report
        assert "dependency_files" in report

        # Verify scan structure
        assert report["scan"]["type"] == "dependency_scanning"
        assert "analyzer" in report["scan"]
        assert "scanner" in report["scan"]
        assert report["scan"]["analyzer"]["id"] == "socket-security"
        assert report["scan"]["scanner"]["id"] == "socket-cli"
        assert report["scan"]["status"] == "success"

        # Timestamps must match GitLab pattern (no microseconds, no trailing Z)
        assert self.GITLAB_TIMESTAMP_RE.match(report["scan"]["start_time"]), \
            f"start_time '{report['scan']['start_time']}' doesn't match GitLab pattern"
        assert self.GITLAB_TIMESTAMP_RE.match(report["scan"]["end_time"]), \
            f"end_time '{report['scan']['end_time']}' doesn't match GitLab pattern"

    def test_vulnerability_mapping(self):
        """Test Socket Issue maps correctly to GitLab vulnerability"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="test-package",
            pkg_version="1.0.0",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            type="malware",
            url="https://socket.dev/test",
            manifests="package.json",
            props={"cve": ["CVE-2024-1234"]},
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-package@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)

        assert len(report["vulnerabilities"]) == 1
        vuln = report["vulnerabilities"][0]

        assert vuln["category"] == "dependency_scanning"
        assert vuln["name"] == "Test Vulnerability"
        assert vuln["severity"] == "High"
        assert vuln["location"]["file"] == "package.json"
        assert vuln["location"]["dependency"]["package"]["name"] == "test-package"
        assert vuln["location"]["dependency"]["version"] == "1.0.0"
        assert vuln["message"] == "test-package@1.0.0: Test Vulnerability"

    def test_identifier_extraction_with_cve(self):
        """Test CVE identifiers are correctly extracted"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="vulnerable-pkg",
            pkg_version="2.0.0",
            type="vulnerability",
            severity="critical",
            title="Known CVE",
            props={"cve": ["CVE-2024-5678", "CVE-2024-9012"]},
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/vulnerable-pkg@2.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        # Should have socket_alert identifier + 2 CVE identifiers
        assert len(vuln["identifiers"]) >= 3
        cve_identifiers = [i for i in vuln["identifiers"] if i["type"] == "cve"]
        assert len(cve_identifiers) == 2
        assert any(i["value"] == "CVE-2024-5678" for i in cve_identifiers)
        assert any(i["value"] == "CVE-2024-9012" for i in cve_identifiers)

    def test_identifier_extraction_with_single_cve_string(self):
        """Test single CVE identifier as string"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="vulnerable-pkg",
            pkg_version="2.0.0",
            type="vulnerability",
            severity="high",
            title="Single CVE",
            props={"cve": "CVE-2024-1111"},
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/vulnerable-pkg@2.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        cve_identifiers = [i for i in vuln["identifiers"] if i["type"] == "cve"]
        assert len(cve_identifiers) == 1
        assert cve_identifiers[0]["value"] == "CVE-2024-1111"

    def test_dependency_chain_handling_transitive(self):
        """Test transitive dependency path is captured"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="transitive-dep",
            pkg_version="1.5.0",
            type="supply-chain-risk",
            severity="medium",
            title="Supply Chain Risk",
            introduced_by=[
                ["top-level > intermediate > transitive-dep", "package.json"]
            ],
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/transitive-dep@1.5.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert vuln["location"]["file"] == "package.json"
        assert vuln["location"]["dependency"]["direct"] is False

    def test_dependency_chain_handling_direct(self):
        """Test direct dependency is correctly identified"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="direct-dep",
            pkg_version="3.0.0",
            type="malware",
            severity="critical",
            title="Malware Found",
            introduced_by=[
                ["direct-dep", "package.json"]
            ],
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/direct-dep@3.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert vuln["location"]["dependency"]["direct"] is True

    def test_severity_mapping(self):
        """Test all Socket severities map to GitLab severities"""
        severity_tests = [
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("middle", "Medium"),  # Old format
            ("low", "Low"),
            ("unknown", "Unknown")
        ]

        for socket_sev, gitlab_sev in severity_tests:
            result = Messages.map_socket_severity_to_gitlab(socket_sev)
            assert result == gitlab_sev, f"Failed for severity: {socket_sev}"

    def test_empty_alerts(self):
        """Test report with no vulnerabilities"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.new_alerts = []

        report = Messages.create_security_comment_gitlab(diff)

        assert len(report["vulnerabilities"]) == 0
        assert report["scan"]["status"] == "success"

    def test_multiple_manifest_files(self):
        """Test handling of multiple manifest files (semicolon-separated)"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="multi-manifest-pkg",
            pkg_version="1.0.0",
            type="supply-chain-risk",
            severity="high",
            title="Multiple Manifests",
            introduced_by=[
                ["multi-manifest-pkg", "package.json;package-lock.json"]
            ],
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/multi-manifest-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        # Should use first manifest file
        assert vuln["location"]["file"] == "package.json"

    def test_solution_field_included(self):
        """Test solution field is included when suggestion is present"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="fixable-pkg",
            pkg_version="1.0.0",
            type="vulnerability",
            severity="high",
            title="Fixable Issue",
            suggestion="Update to version 2.0.0",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/fixable-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert "solution" in vuln
        assert vuln["solution"] == "Update to version 2.0.0"

    def test_solution_field_omitted_when_no_suggestion(self):
        """Test solution field is omitted when no suggestion"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="unfixable-pkg",
            pkg_version="1.0.0",
            type="vulnerability",
            severity="high",
            title="No Fix Available",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/unfixable-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert "solution" not in vuln

    def test_uuid_generation_is_deterministic(self):
        """Test UUID generation is deterministic for same vulnerability"""
        test_issue = Issue(
            pkg_name="test-pkg",
            pkg_version="1.0.0",
            type="malware",
            severity="high",
            title="Test",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-pkg@1.0.0"
        )

        uuid1 = Messages.generate_uuid_from_alert_gitlab(test_issue)
        uuid2 = Messages.generate_uuid_from_alert_gitlab(test_issue)

        assert uuid1 == uuid2

    def test_uuid_generation_differs_for_different_vulnerabilities(self):
        """Test UUID generation differs for different vulnerabilities"""
        issue1 = Issue(
            pkg_name="test-pkg",
            pkg_version="1.0.0",
            type="malware",
            severity="high",
            title="Test",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-pkg@1.0.0"
        )

        issue2 = Issue(
            pkg_name="test-pkg",
            pkg_version="1.0.0",
            type="vulnerability",
            severity="high",
            title="Test",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-pkg@1.0.0"
        )

        uuid1 = Messages.generate_uuid_from_alert_gitlab(issue1)
        uuid2 = Messages.generate_uuid_from_alert_gitlab(issue2)

        assert uuid1 != uuid2

    def test_missing_title_falls_back_to_type(self):
        """Test vulnerability name falls back to type when title missing"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="no-title-pkg",
            pkg_version="1.0.0",
            type="malware",
            severity="high",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/no-title-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert "malware" in vuln["name"].lower()
        assert "no-title-pkg" in vuln["name"]

    def test_links_array_includes_socket_url(self):
        """Test links array includes Socket.dev URL"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="linked-pkg",
            pkg_version="1.0.0",
            type="malware",
            severity="high",
            title="Test",
            url="https://socket.dev/npm/package/linked-pkg",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/linked-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert len(vuln["links"]) == 1
        assert vuln["links"][0]["url"] == "https://socket.dev/npm/package/linked-pkg"

    def test_manifests_attribute_fallback(self):
        """Test location extraction falls back to manifests attribute"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        test_issue = Issue(
            pkg_name="manifest-fallback-pkg",
            pkg_version="1.0.0",
            type="malware",
            severity="high",
            title="Test",
            manifests="requirements.txt",
            pkg_type="pypi",
            key="test-key",
            purl="pkg:pypi/manifest-fallback-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        report = Messages.create_security_comment_gitlab(diff)
        vuln = report["vulnerabilities"][0]

        assert vuln["location"]["file"] == "requirements.txt"

    def test_dependency_files_populated_from_alerts(self):
        """Test dependency_files is built from alert locations per v15.0.0 schema"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        diff.new_alerts = [
            Issue(
                pkg_name="pkg-a",
                pkg_version="1.0.0",
                type="malware",
                severity="high",
                title="Alert A",
                manifests="package.json",
                pkg_type="npm",
                key="key-a",
                purl="pkg:npm/pkg-a@1.0.0"
            ),
            Issue(
                pkg_name="pkg-b",
                pkg_version="2.0.0",
                type="vulnerability",
                severity="medium",
                title="Alert B",
                manifests="requirements.txt",
                pkg_type="pypi",
                key="key-b",
                purl="pkg:pypi/pkg-b@2.0.0"
            ),
        ]

        report = Messages.create_security_comment_gitlab(diff)

        assert "dependency_files" in report
        dep_files = report["dependency_files"]
        assert len(dep_files) == 2

        paths = {df["path"] for df in dep_files}
        assert "package.json" in paths
        assert "requirements.txt" in paths

        for df in dep_files:
            assert "path" in df
            assert "package_manager" in df
            assert "dependencies" in df
            assert isinstance(df["dependencies"], list)
            assert len(df["dependencies"]) >= 1
            for dep in df["dependencies"]:
                assert "package" in dep
                assert "name" in dep["package"]
                assert "version" in dep

    def test_dependency_files_groups_by_manifest(self):
        """Test multiple alerts from the same manifest are grouped into one dependency_file"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        diff.new_alerts = [
            Issue(
                pkg_name="pkg-a", pkg_version="1.0.0", type="malware", severity="high",
                title="A", manifests="package.json", pkg_type="npm", key="k1", purl="pkg:npm/pkg-a@1.0.0"
            ),
            Issue(
                pkg_name="pkg-b", pkg_version="2.0.0", type="vulnerability", severity="low",
                title="B", manifests="package.json", pkg_type="npm", key="k2", purl="pkg:npm/pkg-b@2.0.0"
            ),
        ]

        report = Messages.create_security_comment_gitlab(diff)
        dep_files = report["dependency_files"]

        assert len(dep_files) == 1
        assert dep_files[0]["path"] == "package.json"
        assert dep_files[0]["package_manager"] == "npm"
        assert len(dep_files[0]["dependencies"]) == 2

    def test_dependency_files_empty_when_no_alerts(self):
        """Test dependency_files is an empty array when there are no alerts"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.new_alerts = []

        report = Messages.create_security_comment_gitlab(diff)
        assert report["dependency_files"] == []

    def test_dependency_files_skips_unknown_manifest(self):
        """Test alerts with unknown manifest don't produce dependency_file entries"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        diff.new_alerts = [
            Issue(
                pkg_name="pkg-a", pkg_version="1.0.0", type="malware", severity="high",
                title="A", pkg_type="npm", key="k1", purl="pkg:npm/pkg-a@1.0.0"
            ),
        ]

        report = Messages.create_security_comment_gitlab(diff)
        assert report["dependency_files"] == []

    def test_unchanged_alerts_included_in_report(self):
        """Test that unchanged_alerts are included alongside new_alerts in the GitLab report"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        diff.new_alerts = [
            Issue(
                pkg_name="new-pkg", pkg_version="1.0.0", type="malware", severity="high",
                title="New Alert", manifests="package.json", pkg_type="npm", key="k1", purl="pkg:npm/new-pkg@1.0.0"
            ),
        ]
        diff.unchanged_alerts = [
            Issue(
                pkg_name="existing-pkg", pkg_version="2.0.0", type="vulnerability", severity="medium",
                title="Existing Alert", manifests="package.json", pkg_type="npm", key="k2", purl="pkg:npm/existing-pkg@2.0.0"
            ),
        ]

        report = Messages.create_security_comment_gitlab(diff)
        assert len(report["vulnerabilities"]) == 2

        names = {v["name"] for v in report["vulnerabilities"]}
        assert "New Alert" in names
        assert "Existing Alert" in names

    def test_only_unchanged_alerts_produces_nonempty_report(self):
        """Test that a diff with no new alerts but unchanged alerts still populates the report"""
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"

        diff.new_alerts = []
        diff.unchanged_alerts = [
            Issue(
                pkg_name="stable-pkg", pkg_version="3.0.0", type="vulnerability", severity="critical",
                title="Known Issue", manifests="requirements.txt", pkg_type="pypi", key="k1", purl="pkg:pypi/stable-pkg@3.0.0"
            ),
        ]

        report = Messages.create_security_comment_gitlab(diff)
        assert len(report["vulnerabilities"]) == 1
        assert report["vulnerabilities"][0]["name"] == "Known Issue"
        assert len(report["dependency_files"]) == 1
        assert report["dependency_files"][0]["path"] == "requirements.txt"

    def test_pkg_type_to_package_manager_mapping(self):
        """Test package manager mapping covers common ecosystems"""
        assert Messages._pkg_type_to_package_manager("npm") == "npm"
        assert Messages._pkg_type_to_package_manager("pypi") == "pip"
        assert Messages._pkg_type_to_package_manager("go") == "go"
        assert Messages._pkg_type_to_package_manager("maven") == "maven"
        assert Messages._pkg_type_to_package_manager("gem") == "bundler"
        assert Messages._pkg_type_to_package_manager("nuget") == "nuget"
        assert Messages._pkg_type_to_package_manager("cargo") == "cargo"
        assert Messages._pkg_type_to_package_manager("") == "unknown"
        assert Messages._pkg_type_to_package_manager("swift") == "swift"
