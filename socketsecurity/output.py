import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, List, Set, Tuple
from .core.messages import Messages
from .core.classes import Diff, Issue
from .config import CliConfig
from socketsecurity.plugins.manager import PluginManager
from socketsecurity.core.helper.socket_facts_loader import (
    load_socket_facts,
    get_components_with_vulnerabilities,
    convert_to_alerts,
)
from socketdev import socketdev


class OutputHandler:
    config: CliConfig
    logger: logging.Logger

    def __init__(self, config: CliConfig, sdk: socketdev):
        self.config = config
        self.logger = logging.getLogger("socketcli")

    @staticmethod
    def _normalize_purl(purl: str) -> str:
        if not purl:
            return ""

        normalized = purl.strip().lower().replace("%40", "@")
        if normalized.startswith("pkg:"):
            normalized = normalized[4:]
        return normalized

    @staticmethod
    def _normalize_vuln_id(vuln_id: str) -> str:
        if not vuln_id:
            return ""
        return vuln_id.strip().upper()

    @staticmethod
    def _normalize_pkg_key(pkg_type: str, pkg_name: str, pkg_version: str) -> Tuple[str, str, str]:
        return (
            (pkg_type or "").strip().lower(),
            (pkg_name or "").strip().lower(),
            (pkg_version or "").strip().lower(),
        )

    @staticmethod
    def _extract_issue_vuln_ids(issue: Issue) -> Set[str]:
        ids: Set[str] = set()
        props = getattr(issue, "props", None) or {}
        for key in ("ghsaId", "ghsa_id", "cveId", "cve_id"):
            value = props.get(key)
            if isinstance(value, str) and value.strip():
                ids.add(OutputHandler._normalize_vuln_id(value))
        return ids

    def _load_components_with_alerts(self) -> Optional[List[Dict[str, Any]]]:
        facts_file = self.config.reach_output_file or ".socket.facts.json"
        facts_file_path = str(Path(self.config.target_path or ".") / facts_file)
        facts_data = load_socket_facts(facts_file_path)
        if not facts_data:
            return None

        components = get_components_with_vulnerabilities(facts_data)
        return convert_to_alerts(components)

    def _build_reachability_index(self) -> Optional[Tuple[Dict[str, Set[str]], Dict[Tuple[str, str, str], Set[str]]]]:
        components_with_alerts = self._load_components_with_alerts()
        if not components_with_alerts:
            self.logger.warning(
                "Unable to load reachability facts; falling back to blocking-based SARIF filter"
            )
            return None

        reachable_by_purl: Dict[str, Set[str]] = {}
        reachable_by_pkg: Dict[Tuple[str, str, str], Set[str]] = {}

        for component in components_with_alerts:
            purl = self._normalize_purl(component.get("alerts", [{}])[0].get("props", {}).get("purl", ""))
            pkg_type = component.get("type", "")
            pkg_version = component.get("version", "")
            namespace = (component.get("namespace") or "").strip()
            name = (component.get("name") or component.get("id") or "").strip()

            pkg_names: Set[str] = {name}
            if namespace:
                pkg_names.add(f"{namespace}/{name}")

            for alert in component.get("alerts", []):
                props = alert.get("props", {}) or {}
                if props.get("reachability") != "reachable":
                    continue

                vuln_ids = {
                    self._normalize_vuln_id(props.get("ghsaId", "")),
                    self._normalize_vuln_id(props.get("cveId", "")),
                }
                vuln_ids = {v for v in vuln_ids if v}
                if not vuln_ids:
                    continue

                if purl:
                    if purl not in reachable_by_purl:
                        reachable_by_purl[purl] = set()
                    reachable_by_purl[purl].update(vuln_ids)

                for pkg_name in pkg_names:
                    pkg_key = self._normalize_pkg_key(pkg_type, pkg_name, pkg_version)
                    if pkg_key not in reachable_by_pkg:
                        reachable_by_pkg[pkg_key] = set()
                    reachable_by_pkg[pkg_key].update(vuln_ids)

        return reachable_by_purl, reachable_by_pkg

    def _is_alert_reachable(
        self,
        alert: Issue,
        reachable_by_purl: Dict[str, Set[str]],
        reachable_by_pkg: Dict[Tuple[str, str, str], Set[str]],
    ) -> bool:
        alert_ids = self._extract_issue_vuln_ids(alert)
        alert_purl = self._normalize_purl(getattr(alert, "purl", ""))
        pkg_key = self._normalize_pkg_key(
            getattr(alert, "pkg_type", ""),
            getattr(alert, "pkg_name", ""),
            getattr(alert, "pkg_version", ""),
        )

        if alert_ids:
            if alert_purl and alert_purl in reachable_by_purl and alert_ids.intersection(reachable_by_purl[alert_purl]):
                return True
            if pkg_key in reachable_by_pkg and alert_ids.intersection(reachable_by_pkg[pkg_key]):
                return True
            return False

        if alert_purl and alert_purl in reachable_by_purl:
            return True
        return pkg_key in reachable_by_pkg

    def _filter_sarif_reachable_alerts(self, alerts: List[Issue]) -> List[Issue]:
        reachability_index = self._build_reachability_index()
        if not reachability_index:
            return [a for a in alerts if getattr(a, "error", False)]

        reachable_by_purl, reachable_by_pkg = reachability_index
        return [a for a in alerts if self._is_alert_reachable(a, reachable_by_purl, reachable_by_pkg)]

    def handle_output(self, diff_report: Diff) -> None:
        """Main output handler that determines output format"""
        # Determine which formats to output
        formats_to_output = []

        if self.config.enable_json:
            formats_to_output.append('json')
        if self.config.enable_sarif:
            formats_to_output.append('sarif')
        if self.config.enable_gitlab_security:
            formats_to_output.append('gitlab')

        # If no format specified, default to console comments
        if not formats_to_output:
            self.output_console_comments(diff_report, self.config.sbom_file)
        else:
            # Output all enabled formats
            for format_type in formats_to_output:
                if format_type == 'json':
                    self.output_console_json(diff_report, self.config.sbom_file)
                elif format_type == 'sarif':
                    self.output_console_sarif(diff_report, self.config.sbom_file)
                elif format_type == 'gitlab':
                    self.output_gitlab_security(diff_report)
        if self.config.jira_plugin.enabled:
            jira_config = {
                "enabled": self.config.jira_plugin.enabled,
                "levels": self.config.jira_plugin.levels or [],
                **(self.config.jira_plugin.config or {})
            }
            plugin_mgr = PluginManager({"jira": jira_config})
            plugin_mgr.send(diff_report, config=self.config)

        # Debug Slack webhook configuration when debug is enabled (always show when debug is on)
        if self.config.enable_debug:
            import os
            slack_enabled_env = os.getenv("SOCKET_SLACK_ENABLED", "Not set")
            slack_config_env = os.getenv("SOCKET_SLACK_CONFIG_JSON", "Not set")
            slack_url = "Not configured"
            if self.config.slack_plugin.config and self.config.slack_plugin.config.get("url"):
                slack_url = self.config.slack_plugin.config.get("url")
            slack_mode = (self.config.slack_plugin.config or {}).get("mode", "webhook")
            bot_token = os.getenv("SOCKET_SLACK_BOT_TOKEN")
            bot_token_status = "Set" if bot_token else "Not set"
            self.logger.debug("=== Slack Webhook Debug Information ===")
            self.logger.debug(f"Slack Plugin Enabled: {self.config.slack_plugin.enabled}")
            self.logger.debug(f"Slack Mode: {slack_mode}")
            self.logger.debug(f"SOCKET_SLACK_ENABLED environment variable: {slack_enabled_env}")
            self.logger.debug(f"SOCKET_SLACK_CONFIG_JSON environment variable: {slack_config_env}")
            self.logger.debug(f"Slack Webhook URL: {slack_url}")
            self.logger.debug(f"SOCKET_SLACK_BOT_TOKEN: {bot_token_status}")
            self.logger.debug(f"Slack Alert Levels: {self.config.slack_plugin.levels}")
            if self.config.reach:
                facts_path = os.path.join(self.config.target_path or ".", self.config.reach_output_file or ".socket.facts.json")
                self.logger.debug(f"Reachability facts file: {facts_path} (exists: {os.path.exists(facts_path)})")
            self.logger.debug("=====================================")

        if self.config.slack_plugin.enabled:
            slack_config = {
                "enabled": self.config.slack_plugin.enabled,
                "levels": self.config.slack_plugin.levels or [],
                **(self.config.slack_plugin.config or {})
            }

            plugin_mgr = PluginManager({"slack": slack_config})
            plugin_mgr.send(diff_report, config=self.config)

        self.save_sbom_file(diff_report, self.config.sbom_file)
    
    def return_exit_code(self, diff_report: Diff) -> int:
        if self.config.disable_blocking:
            return 0
        
        if not self.report_pass(diff_report):
            return 1

        # if there are only warn alerts should be returning 0. This was not intended behavior
        # if len(diff_report.new_alerts) > 0:
        #     # 5 means warning alerts but no blocking alerts
        #     return 5
        return 0    

    def output_console_comments(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Outputs formatted console comments"""
        has_new_alerts = len(diff_report.new_alerts) > 0
        has_unchanged_alerts = (
            self.config.strict_blocking and
            hasattr(diff_report, 'unchanged_alerts') and
            len(diff_report.unchanged_alerts) > 0
        )

        if not has_new_alerts and not has_unchanged_alerts:
            self.logger.info("No issues found")
            return

        # Count blocking vs warning alerts
        new_blocking = sum(1 for issue in diff_report.new_alerts if issue.error)
        new_warning = sum(1 for issue in diff_report.new_alerts if issue.warn)

        unchanged_blocking = 0
        unchanged_warning = 0
        if has_unchanged_alerts:
            unchanged_blocking = sum(1 for issue in diff_report.unchanged_alerts if issue.error)
            unchanged_warning = sum(1 for issue in diff_report.unchanged_alerts if issue.warn)

        console_security_comment = Messages.create_console_security_alert_table(diff_report)

        # Build status message
        self.logger.info("Security issues detected by Socket Security:")
        if new_blocking > 0:
            self.logger.info(f"  - NEW blocking issues: {new_blocking}")
        if new_warning > 0:
            self.logger.info(f"  - NEW warning issues: {new_warning}")
        if unchanged_blocking > 0:
            self.logger.info(f"  - EXISTING blocking issues: {unchanged_blocking} (causing failure due to --strict-blocking)")
        if unchanged_warning > 0:
            self.logger.info(f"  - EXISTING warning issues: {unchanged_warning}")

        self.logger.info(f"Diff Url: {diff_report.diff_url}")
        self.logger.info(f"\n{console_security_comment}")

    def output_console_json(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Outputs JSON formatted results"""
        console_security_comment = Messages.create_security_comment_json(diff_report)
        self.save_sbom_file(diff_report, sbom_file_name)
        self.logger.info(json.dumps(console_security_comment))

    def output_console_sarif(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """
        Generate SARIF output from the diff report and print to console.
        If --sarif-file is configured, also save to file.
        Scope:
        - diff (default): SARIF from diff.new_alerts
        - full: SARIF from .socket.facts.json alerts
        """
        sarif_scope = getattr(self.config, "sarif_scope", "diff")
        sarif_grouping = getattr(self.config, "sarif_grouping", "instance")
        sarif_reachability = getattr(self.config, "sarif_reachability", "all")
        if sarif_grouping not in {"instance", "alert"}:
            sarif_grouping = "instance"
        if sarif_reachability not in {"all", "reachable", "potentially", "reachable-or-potentially"}:
            sarif_reachability = "all"
        if getattr(self.config, "sarif_reachable_only", False) is True:
            sarif_reachability = "reachable"
        if diff_report.id != "NO_DIFF_RAN" or sarif_scope == "full":
            if sarif_scope == "full":
                components_with_alerts = self._load_components_with_alerts()
                if not components_with_alerts:
                    self.logger.error(
                        "Unable to generate full-scope SARIF: .socket.facts.json missing or invalid"
                    )
                    components_with_alerts = []
                console_security_comment = Messages.create_security_comment_sarif_from_facts(
                    components_with_alerts,
                    reachability_filter=sarif_reachability,
                    grouping=sarif_grouping,
                )
            else:
                if sarif_reachability == "reachable":
                    filtered_alerts = self._filter_sarif_reachable_alerts(diff_report.new_alerts)
                    diff_report = Diff(
                        new_alerts=filtered_alerts,
                        diff_url=getattr(diff_report, "diff_url", ""),
                        new_packages=getattr(diff_report, "new_packages", []),
                        removed_packages=getattr(diff_report, "removed_packages", []),
                        packages=getattr(diff_report, "packages", {}),
                    )
                    diff_report.id = "filtered"
                elif sarif_reachability != "all":
                    self.logger.warning(
                        "Reachability filter '%s' is only supported in full SARIF scope; output is unfiltered in diff scope",
                        sarif_reachability,
                    )

                # Generate the SARIF structure using Messages
                console_security_comment = Messages.create_security_comment_sarif(diff_report)
            self.save_sbom_file(diff_report, sbom_file_name)
            # Avoid flooding logs for full-scope SARIF when writing to file.
            if not (sarif_scope == "full" and self.config.sarif_file):
                # Print the SARIF output to the console in JSON format
                print(json.dumps(console_security_comment, indent=2))
            else:
                self.logger.info(
                    "SARIF stdout output suppressed for full scope; report will be written to --sarif-file"
                )

            # Save to file if --sarif-file is specified
            if self.config.sarif_file:
                sarif_path = Path(self.config.sarif_file)
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                with open(sarif_path, "w") as f:
                    json.dump(console_security_comment, f, indent=2)
                self.logger.info(f"SARIF report saved to {self.config.sarif_file}")

    def report_pass(self, diff_report: Diff) -> bool:
        """Determines if the report passes security checks"""
        # Priority 1: --disable-blocking always passes
        if self.config.disable_blocking:
            return True

        # Check new alerts for blocking issues
        has_new_blocking_alerts = any(issue.error for issue in diff_report.new_alerts)

        # Check unchanged alerts if --strict-blocking is enabled
        has_unchanged_blocking_alerts = False
        if self.config.strict_blocking and hasattr(diff_report, 'unchanged_alerts'):
            has_unchanged_blocking_alerts = any(
                issue.error for issue in diff_report.unchanged_alerts
            )

        # If no alerts at all, pass
        if not diff_report.new_alerts and not (
            self.config.strict_blocking and
            hasattr(diff_report, 'unchanged_alerts') and
            diff_report.unchanged_alerts
        ):
            return True

        # Fail if there are any blocking alerts (new or unchanged with --strict-blocking)
        return not (has_new_blocking_alerts or has_unchanged_blocking_alerts)

    def save_sbom_file(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Saves SBOM file if filename is provided"""
        if not sbom_file_name or not diff_report.sbom:
            return

        sbom_path = Path(sbom_file_name)
        sbom_path.parent.mkdir(parents=True, exist_ok=True)

        with open(sbom_path, "w") as f:
            json.dump(diff_report.sbom, f, indent=2)

    def output_gitlab_security(self, diff_report: Diff) -> None:
        """
        Generate GitLab Security Dashboard (Dependency Scanning) output
        and save to file.

        Args:
            diff_report: Diff report containing vulnerability data
        """
        if diff_report.id != "NO_DIFF_RAN":
            # Generate GitLab report structure
            gitlab_report = Messages.create_security_comment_gitlab(diff_report)

            # Determine output file path
            output_path = self.config.gitlab_security_file or "gl-dependency-scanning-report.json"

            # Save to file
            self.save_gitlab_security_file(gitlab_report, output_path)

            self.logger.info(f"GitLab Security report saved to {output_path}")

    def save_gitlab_security_file(self, report: dict, file_path: str) -> None:
        """
        Save GitLab Security Dashboard report to file.

        Args:
            report: GitLab report dictionary
            file_path: Path to save the report file
        """
        gitlab_path = Path(file_path)
        gitlab_path.parent.mkdir(parents=True, exist_ok=True)

        with open(gitlab_path, "w") as f:
            json.dump(report, f, indent=2)

    def _output_issue(self, issue: Issue) -> None:
        """Helper method to format and output a single issue"""
        severity = issue.severity.upper() if issue.severity else "UNKNOWN"
        status = "🚫 Blocking" if issue.error else "⚠️ Warning"

        self.logger.warning(f"\n{status} - Severity: {severity}")
        self.logger.warning(f"Title: {issue.title}")
        if issue.description:
            self.logger.warning(f"Description: {issue.description}")
        if issue.suggestion:
            self.logger.warning(f"suggestion: {issue.suggestion}")

    def _format_issue(self, issue: Issue) -> Dict[str, Any]:
        """Helper method to format an issue for JSON output"""
        return {
            "purl": issue.purl,
            "title": issue.title,
            "description": issue.description,
            "severity": issue.severity,
            "blocking": issue.error,
        }
