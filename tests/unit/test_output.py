import pytest
from socketsecurity.output import OutputHandler
from socketsecurity.core.classes import Diff, Issue
import json

class TestOutputHandler:
    @pytest.fixture
    def handler(self):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock
        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = False
        config.sarif_file = None
        config.sarif_reachability = "all"
        config.sarif_scope = "diff"
        config.sarif_grouping = "instance"
        config.sarif_reachability = "all"
        config.sbom_file = None
        return OutputHandler(config, Mock())

    def test_report_pass_with_blocking_issues(self, handler):
        diff = Diff()
        diff.new_alerts = [Issue(error=True)]
        assert not handler.report_pass(diff)

    def test_report_pass_with_blocking_disabled(self):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock
        config = Mock(spec=CliConfig)
        config.disable_blocking = True
        config.strict_blocking = False
        handler = OutputHandler(config, Mock())
        diff = Diff()
        diff.new_alerts = [Issue(error=True)]
        assert handler.report_pass(diff)

    def test_json_output_format(self, handler, caplog):
        import logging
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        test_issue = Issue(
            title="Test",
            severity="high",
            description="Test description",
            error=True,
            key="test-key",
            type="test-type",
            pkg_type="npm",
            pkg_name="test-package",
            pkg_version="1.0.0",
            purl="pkg:npm/test-package@1.0.0"
        )
        diff.new_alerts = [test_issue]

        with caplog.at_level(logging.INFO, logger="socketcli"):
            handler.output_console_json(diff)

        output = json.loads(caplog.messages[-1])
        assert output["new_alerts"][0]["title"] == "Test"
        assert output["new_alerts"][0]["severity"] == "high"
        assert output["new_alerts"][0]["error"] is True
        assert output["new_alerts"][0]["description"] == "Test description"

    def test_json_output_includes_unchanged_alerts_with_strict_blocking(self, caplog):
        import logging
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.new_alerts = [
            Issue(
                title="New",
                severity="high",
                description="new",
                error=True,
                key="new-key",
                type="test-type",
                pkg_type="npm",
                pkg_name="new-package",
                pkg_version="1.0.0",
                purl="pkg:npm/new-package@1.0.0",
            )
        ]
        diff.unchanged_alerts = [
            Issue(
                title="Existing",
                severity="high",
                description="existing",
                error=True,
                key="existing-key",
                type="test-type",
                pkg_type="npm",
                pkg_name="existing-package",
                pkg_version="1.0.0",
                purl="pkg:npm/existing-package@1.0.0",
            )
        ]

        with caplog.at_level(logging.INFO, logger="socketcli"):
            handler.output_console_json(diff)

        output = json.loads(caplog.messages[-1])
        assert len(output["new_alerts"]) == 2
        titles = {a["title"] for a in output["new_alerts"]}
        assert titles == {"New", "Existing"}

    def test_sbom_file_saving(self, handler, tmp_path):
        # Test SBOM file is created correctly
        diff = Diff()
        diff.sbom = {"test": "data"}
        sbom_path = tmp_path / "test.json"
        handler.save_sbom_file(diff, str(sbom_path))
        assert sbom_path.exists()

    def test_sbom_file_saving_without_sbom_writes_empty_array(self, handler, tmp_path):
        diff = Diff()
        sbom_path = tmp_path / "empty.json"
        handler.save_sbom_file(diff, str(sbom_path))
        assert sbom_path.exists()
        assert json.loads(sbom_path.read_text()) == []

    def test_json_file_saving(self, tmp_path):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        json_path = tmp_path / "report.json"

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = False
        config.json_file = str(json_path)
        config.summary_file = None
        config.report_link_file = None
        config.sbom_file = None
        config.legal = True
        config.repo = "owner/repo"
        config.branch = "main"
        config.commit_sha = "abc123"
        config.enable_json = False
        config.enable_sarif = False
        config.enable_gitlab_security = False
        config.enable_debug = False

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "scan-123"
        diff.diff_url = "https://socket.dev/diff/123"
        diff.report_url = "https://socket.dev/report/123"
        diff.new_alerts = [
            Issue(
                title="Test",
                severity="high",
                description="desc",
                error=True,
                key="test-key",
                type="vulnerability",
                pkg_type="npm",
                pkg_name="test-package",
                pkg_version="1.0.0",
                purl="pkg:npm/test-package@1.0.0",
                url="https://socket.dev/npm/package/test-package/alerts/1.0.0",
            )
        ]

        handler.save_json_file(diff, str(json_path))

        saved = json.loads(json_path.read_text())
        assert saved["full_scan_id"] == "scan-123"
        assert saved["report_url"] == "https://socket.dev/report/123"
        assert saved["repo"] == "owner/repo"
        assert saved["branch"] == "main"
        assert saved["commit_sha"] == "abc123"
        assert saved["legal_mode"] is True

    def test_summary_and_report_link_files_are_written(self, tmp_path):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        summary_path = tmp_path / "summary.txt"
        report_link_path = tmp_path / "report-link.txt"

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = False
        config.json_file = None
        config.summary_file = str(summary_path)
        config.report_link_file = str(report_link_path)
        config.sbom_file = None
        config.legal = False
        config.repo = None
        config.branch = ""
        config.commit_sha = ""
        config.enable_json = False
        config.enable_sarif = False
        config.enable_gitlab_security = False
        config.enable_debug = False

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "scan-123"
        diff.diff_url = "https://socket.dev/diff/123"
        diff.report_url = "https://socket.dev/report/123"
        diff.new_alerts = [
            Issue(
                title="Test",
                severity="high",
                description="desc",
                error=True,
                key="test-key",
                type="vulnerability",
                pkg_type="npm",
                pkg_name="test-package",
                pkg_version="1.0.0",
                purl="pkg:npm/test-package@1.0.0",
                url="https://socket.dev/npm/package/test-package/alerts/1.0.0",
            )
        ]

        handler.save_summary_file(diff, str(summary_path))
        handler.save_report_link_file(diff, str(report_link_path))

        assert "Security issues detected by Socket Security:" in summary_path.read_text()
        assert report_link_path.read_text().strip() == "https://socket.dev/report/123"

    def test_report_pass_with_strict_blocking_new_alerts(self):
        """Test that strict-blocking fails on new blocking alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        # Create config with strict_blocking
        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=True, warn=False)]
        diff.unchanged_alerts = []

        assert not handler.report_pass(diff)

    def test_report_pass_with_strict_blocking_unchanged_alerts(self):
        """Test that strict-blocking fails on unchanged blocking alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = []
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        assert not handler.report_pass(diff)

    def test_report_pass_with_strict_blocking_both_alerts(self):
        """Test that strict-blocking fails when both new and unchanged alerts exist"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=True, warn=False)]
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        assert not handler.report_pass(diff)

    def test_report_pass_with_strict_blocking_only_warnings(self):
        """Test that strict-blocking passes when only warnings (not errors) exist"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=False, warn=True)]
        diff.unchanged_alerts = [Issue(error=False, warn=True)]

        assert handler.report_pass(diff)

    def test_report_pass_strict_blocking_disabled(self):
        """Test that strict-blocking without the flag passes with unchanged alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = False  # Flag not set

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = []
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        # Should pass because strict_blocking is False
        assert handler.report_pass(diff)

    def test_disable_blocking_overrides_strict_blocking(self):
        """Test that disable-blocking takes precedence over strict-blocking"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = True
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=True, warn=False)]
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        # Should pass because disable_blocking takes precedence
        assert handler.report_pass(diff)

    def test_sarif_file_output(self, tmp_path):
        """Test that --sarif-file writes SARIF report to a file"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_scope = "diff"
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [Issue(
            pkg_name="test-package",
            pkg_version="1.0.0",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            type="malware",
            url="https://socket.dev/test",
            manifests="package.json",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-package@1.0.0",
            error=True,
        )]

        handler.output_console_sarif(diff)

        assert sarif_path.exists()
        with open(sarif_path) as f:
            sarif_data = json.load(f)
        assert sarif_data["version"] == "2.1.0"

    def test_sarif_reachability_reachable_filters_non_reachable(self, tmp_path):
        """Test that --sarif-reachability reachable uses .socket.facts.json reachability."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"
        facts_path = tmp_path / ".socket.facts.json"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_reachability = "reachable"
        config.sarif_scope = "diff"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())

        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "reachable-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [{"ghsaId": "GHSA-AAAA-BBBB-CCCC", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
                        "reachability": [{"type": "reachable"}]
                    }]
                },
                {
                    "type": "npm",
                    "name": "unreachable-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [{"ghsaId": "GHSA-DDDD-EEEE-FFFF", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-DDDD-EEEE-FFFF",
                        "reachability": [{"type": "unreachable"}]
                    }]
                }
            ]
        }))

        def make_issue(name, error, ghsa_id):
            return Issue(
                pkg_name=name,
                pkg_version="1.0.0",
                severity="high",
                title=f"Vuln in {name}",
                description="test",
                type="vulnerability",
                manifests="package.json",
                pkg_type="npm",
                key=f"key-{name}",
                purl=f"pkg:npm/{name}@1.0.0",
                error=error,
                props={"ghsaId": ghsa_id},
            )

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [
            make_issue("reachable-pkg", error=False, ghsa_id="GHSA-AAAA-BBBB-CCCC"),
            make_issue("unreachable-pkg", error=True, ghsa_id="GHSA-DDDD-EEEE-FFFF"),
        ]

        handler.output_console_sarif(diff)

        with open(sarif_path) as f:
            sarif_data = json.load(f)

        rule_ids = [r["ruleId"] for r in sarif_data["runs"][0]["results"]]
        assert any("reachable-pkg" in r for r in rule_ids)
        assert not any("unreachable-pkg" in r for r in rule_ids)

    def test_sarif_reachability_reachable_falls_back_to_blocking_when_facts_missing(self, tmp_path):
        """Test that missing facts file falls back to historical blocking filter."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_reachability = "reachable"
        config.sarif_scope = "diff"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [
            Issue(pkg_name="blocking-pkg", pkg_version="1.0.0", severity="high",
                  title="Vuln", description="test", type="vulnerability",
                  manifests="package.json", pkg_type="npm", key="k1",
                  purl="pkg:npm/blocking-pkg@1.0.0", error=True),
            Issue(pkg_name="warn-pkg", pkg_version="1.0.0", severity="low",
                  title="Vuln", description="test", type="vulnerability",
                  manifests="package.json", pkg_type="npm", key="k2",
                  purl="pkg:npm/warn-pkg@1.0.0", error=False),
        ]

        handler.output_console_sarif(diff)

        with open(sarif_path) as f:
            sarif_data = json.load(f)

        rule_ids = [r["ruleId"] for r in sarif_data["runs"][0]["results"]]
        assert any("blocking-pkg" in r for r in rule_ids)
        assert not any("warn-pkg" in r for r in rule_ids)

    def test_sarif_output_includes_unchanged_with_strict_blocking(self, tmp_path):
        """Strict blocking should include unchanged alerts in diff-scope SARIF output."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path_strict_false = tmp_path / "strict-false.sarif"
        sarif_path_strict_true = tmp_path / "strict-true.sarif"

        def build_handler(strict_blocking, output_path):
            config = Mock(spec=CliConfig)
            config.sarif_file = str(output_path)
            config.sarif_reachability = "all"
            config.sarif_scope = "diff"
            config.sbom_file = None
            config.strict_blocking = strict_blocking
            config.target_path = str(tmp_path)
            config.reach_output_file = ".socket.facts.json"
            return OutputHandler(config, Mock())

        def build_diff():
            diff = Diff()
            diff.id = "test-scan-id"
            diff.new_alerts = [
                Issue(pkg_name="pkg-a", pkg_version="1.0.0", severity="high",
                      title="Vuln A", description="test", type="vulnerability",
                      manifests="package.json", pkg_type="npm", key="a",
                      purl="pkg:npm/pkg-a@1.0.0", error=True),
            ]
            diff.unchanged_alerts = [
                Issue(pkg_name="pkg-old", pkg_version="1.0.0", severity="high",
                      title="Old Vuln", description="test", type="vulnerability",
                      manifests="package.json", pkg_type="npm", key="old",
                      purl="pkg:npm/pkg-old@1.0.0", error=True),
            ]
            return diff

        handler_false = build_handler(False, sarif_path_strict_false)
        handler_true = build_handler(True, sarif_path_strict_true)

        handler_false.output_console_sarif(build_diff())
        handler_true.output_console_sarif(build_diff())

        with open(sarif_path_strict_false) as f:
            sarif_false = json.load(f)
        with open(sarif_path_strict_true) as f:
            sarif_true = json.load(f)

        false_rule_ids = [r["ruleId"] for r in sarif_false["runs"][0]["results"]]
        true_rule_ids = [r["ruleId"] for r in sarif_true["runs"][0]["results"]]

        assert any("pkg-a" in r for r in false_rule_ids)
        assert not any("pkg-old" in r for r in false_rule_ids)
        assert any("pkg-a" in r for r in true_rule_ids)
        assert any("pkg-old" in r for r in true_rule_ids)

    def test_sarif_reachability_all_includes_all(self, tmp_path):
        """Test that --sarif-reachability all includes all alerts."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_reachability = "all"
        config.sarif_scope = "diff"
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [
            Issue(pkg_name="blocking-pkg", pkg_version="1.0.0", severity="high",
                  title="Vuln", description="test", type="vulnerability",
                  manifests="package.json", pkg_type="npm", key="k1",
                  purl="pkg:npm/blocking-pkg@1.0.0", error=True),
            Issue(pkg_name="non-blocking-pkg", pkg_version="1.0.0", severity="low",
                  title="Vuln", description="test", type="vulnerability",
                  manifests="package.json", pkg_type="npm", key="k2",
                  purl="pkg:npm/non-blocking-pkg@1.0.0", error=False),
        ]

        handler.output_console_sarif(diff)

        with open(sarif_path) as f:
            sarif_data = json.load(f)

        rule_ids = [r["ruleId"] for r in sarif_data["runs"][0]["results"]]
        assert any("blocking-pkg" in r for r in rule_ids)
        assert any("non-blocking-pkg" in r for r in rule_ids)
        assert "$schema" in sarif_data
        assert len(sarif_data["runs"]) == 1

    def test_sarif_no_file_when_not_configured(self, tmp_path):
        """Test that no file is written when --sarif-file is not set"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.sarif_file = None
        config.sarif_scope = "diff"
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = []

        handler.output_console_sarif(diff)

        # No files should be created in tmp_path
        assert list(tmp_path.iterdir()) == []

    def test_sarif_file_nested_directory(self, tmp_path):
        """Test that --sarif-file creates parent directories if needed"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "nested" / "dir" / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_scope = "diff"
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = []

        handler.output_console_sarif(diff)

        assert sarif_path.exists()
        with open(sarif_path) as f:
            sarif_data = json.load(f)
        assert sarif_data["version"] == "2.1.0"

    def test_sarif_scope_full_before_after_reachable_filtering_snapshot(self, tmp_path):
        """Full-scope SARIF should show before/after changes with reachable-only filtering."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        facts_path = tmp_path / ".socket.facts.json"
        all_path = tmp_path / "full-all.sarif"
        reachable_path = tmp_path / "full-reachable.sarif"

        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "pkg-reach",
                    "version": "1.0.0",
                    "manifestFiles": ["package.json"],
                    "vulnerabilities": [{"ghsaId": "GHSA-1111-2222-3333", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-1111-2222-3333",
                        "reachability": [{"type": "reachable"}]
                    }]
                },
                {
                    "type": "npm",
                    "name": "pkg-unreach",
                    "version": "2.0.0",
                    "manifestFiles": ["package-lock.json"],
                    "vulnerabilities": [{"ghsaId": "GHSA-4444-5555-6666", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-4444-5555-6666",
                        "reachability": [{"type": "unreachable"}]
                    }]
                }
            ]
        }))

        def build_handler(output_path, reachable_only):
            config = Mock(spec=CliConfig)
            config.sarif_file = str(output_path)
            config.sarif_reachability = "reachable" if reachable_only else "all"
            config.sarif_scope = "full"
            config.sbom_file = None
            config.target_path = str(tmp_path)
            config.reach_output_file = ".socket.facts.json"
            return OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = []  # Full scope should not depend on diff alerts

        handler_all = build_handler(all_path, reachable_only=False)
        handler_all.output_console_sarif(diff)
        with open(all_path) as f:
            sarif_all = json.load(f)

        handler_reachable = build_handler(reachable_path, reachable_only=True)
        handler_reachable.output_console_sarif(diff)
        with open(reachable_path) as f:
            sarif_reachable = json.load(f)

        all_results = sarif_all["runs"][0]["results"]
        reachable_results = sarif_reachable["runs"][0]["results"]

        # Before: includes reachable + unreachable
        assert len(all_results) == 2
        # After applying reachable-only: only reachable remains
        assert len(reachable_results) == 1
        assert reachable_results[0]["properties"]["reachability"] == "reachable"

    def test_sarif_scope_full_works_when_diff_not_run(self, tmp_path):
        """Full scope should still emit SARIF when diff id is NO_DIFF_RAN."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        facts_path = tmp_path / ".socket.facts.json"
        out_path = tmp_path / "full-no-diff.sarif"

        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "pkg-reach",
                    "version": "1.0.0",
                    "manifestFiles": ["package.json"],
                    "vulnerabilities": [{"ghsaId": "GHSA-1111-2222-3333", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-1111-2222-3333",
                        "reachability": [{"type": "reachable"}]
                    }]
                }
            ]
        }))

        config = Mock(spec=CliConfig)
        config.sarif_file = str(out_path)
        config.sarif_reachability = "reachable"
        config.sarif_scope = "full"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "NO_DIFF_RAN"
        diff.new_alerts = []

        handler.output_console_sarif(diff)

        with open(out_path) as f:
            sarif = json.load(f)

        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_scope_full_dedupes_duplicate_manifest_uris(self, tmp_path):
        """Full scope should not emit duplicate results for duplicate manifest entries."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        facts_path = tmp_path / ".socket.facts.json"
        out_path = tmp_path / "full-dedup.sarif"

        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "pkg-reach",
                    "version": "1.0.0",
                    "manifestFiles": ["package.json", "package.json"],
                    "vulnerabilities": [{"ghsaId": "GHSA-1111-2222-3333", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-1111-2222-3333",
                        "reachability": [{"type": "reachable"}]
                    }]
                }
            ]
        }))

        config = Mock(spec=CliConfig)
        config.sarif_file = str(out_path)
        config.sarif_reachability = "reachable"
        config.sarif_scope = "full"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())

        diff = Diff(id="snapshot", new_alerts=[])
        handler.output_console_sarif(diff)

        with open(out_path) as f:
            sarif = json.load(f)

        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_scope_full_with_sarif_file_suppresses_stdout(self, tmp_path, capsys):
        """Full scope + --sarif-file should avoid printing massive SARIF JSON to stdout."""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        facts_path = tmp_path / ".socket.facts.json"
        out_path = tmp_path / "full-suppressed.sarif"

        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "pkg-reach",
                    "version": "1.0.0",
                    "manifestFiles": ["package.json"],
                    "vulnerabilities": [{"ghsaId": "GHSA-1111-2222-3333", "severity": "HIGH"}],
                    "reachability": [{
                        "ghsa_id": "GHSA-1111-2222-3333",
                        "reachability": [{"type": "reachable"}]
                    }]
                }
            ]
        }))

        config = Mock(spec=CliConfig)
        config.sarif_file = str(out_path)
        config.sarif_reachability = "reachable"
        config.sarif_scope = "full"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())
        diff = Diff(id="snapshot", new_alerts=[])

        handler.output_console_sarif(diff)
        captured = capsys.readouterr()

        assert captured.out == ""
        assert out_path.exists()

    def test_sarif_scope_full_alert_grouping_dedupes_versions(self, tmp_path):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        out_path = tmp_path / "full-alert-grouping.sarif"
        facts_path = tmp_path / ".socket.facts.json"
        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "tmp",
                    "version": "0.1.0",
                    "manifestFiles": [{"path": "package-lock.json"}],
                    "vulnerabilities": [{"ghsaId": "GHSA-x", "range": "<0.2.4", "severity": "high"}],
                    "reachability": [{"ghsa_id": "GHSA-x", "reachability": [{"type": "reachable"}]}],
                },
                {
                    "type": "npm",
                    "name": "tmp",
                    "version": "0.0.24",
                    "manifestFiles": [{"path": "package-lock.json"}],
                    "vulnerabilities": [{"ghsaId": "GHSA-x", "range": "<0.2.4", "severity": "high"}],
                    "reachability": [{"ghsa_id": "GHSA-x", "reachability": [{"type": "reachable"}]}],
                },
            ]
        }))

        config = Mock(spec=CliConfig)
        config.sarif_file = str(out_path)
        config.sarif_reachability = "all"
        config.sarif_scope = "full"
        config.sarif_grouping = "alert"
        config.sarif_reachability = "reachable"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())
        diff = Diff(id="snapshot", new_alerts=[])

        handler.output_console_sarif(diff)
        with open(out_path) as f:
            sarif = json.load(f)

        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        props = results[0]["properties"]
        assert sorted(props["versions"]) == ["0.0.24", "0.1.0"]
        assert props["reachability"] == "reachable"

    def test_sarif_scope_full_potentially_filter(self, tmp_path):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        out_path = tmp_path / "full-potentially.sarif"
        facts_path = tmp_path / ".socket.facts.json"
        facts_path.write_text(json.dumps({
            "components": [
                {
                    "type": "npm",
                    "name": "alpha",
                    "version": "1.0.0",
                    "manifestFiles": [{"path": "package-lock.json"}],
                    "vulnerabilities": [{"ghsaId": "GHSA-reach", "range": "<2.0.0", "severity": "high"}],
                    "reachability": [{"ghsa_id": "GHSA-reach", "reachability": [{"type": "reachable"}]}],
                },
                {
                    "type": "npm",
                    "name": "beta",
                    "version": "1.0.0",
                    "manifestFiles": [{"path": "package-lock.json"}],
                    "vulnerabilities": [{"ghsaId": "GHSA-unknown", "range": "<2.0.0", "severity": "high"}],
                    "reachability": [{"ghsa_id": "GHSA-unknown", "reachability": [{"type": "unknown"}]}],
                },
            ]
        }))

        config = Mock(spec=CliConfig)
        config.sarif_file = str(out_path)
        config.sarif_reachability = "all"
        config.sarif_scope = "full"
        config.sarif_grouping = "instance"
        config.sarif_reachability = "potentially"
        config.sbom_file = None
        config.target_path = str(tmp_path)
        config.reach_output_file = ".socket.facts.json"

        handler = OutputHandler(config, Mock())
        diff = Diff(id="snapshot", new_alerts=[])

        handler.output_console_sarif(diff)
        with open(out_path) as f:
            sarif = json.load(f)

        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"].startswith("beta==1.0.0")
