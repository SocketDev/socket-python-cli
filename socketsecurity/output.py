import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from .core.messages import Messages
from .core.classes import Diff, Issue
from .config import CliConfig
from socketsecurity.plugins.manager import PluginManager
from socketsecurity.core.alert_selection import (
    clone_diff_with_selected_alerts,
    filter_alerts_by_reachability,
    load_components_with_alerts,
    select_diff_alerts,
)
from socketdev import socketdev


class OutputHandler:
    config: CliConfig
    logger: logging.Logger

    def __init__(self, config: CliConfig, sdk: socketdev):
        self.config = config
        self.logger = logging.getLogger("socketcli")

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

        self.save_json_file(diff_report, getattr(self.config, "json_file", None))
        self.save_summary_file(diff_report, getattr(self.config, "summary_file", None))
        self.save_report_link_file(diff_report, getattr(self.config, "report_link_file", None))
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
        summary_text = self.build_summary_text(diff_report)
        for line in summary_text.splitlines():
            self.logger.info(line)
        if not summary_text.strip():
            self.logger.info("")

    def output_console_json(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Outputs JSON formatted results"""
        console_security_comment = self.build_json_report(diff_report)
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
        if diff_report.id != "NO_DIFF_RAN" or sarif_scope == "full":
            if sarif_scope == "full":
                components_with_alerts = load_components_with_alerts(
                    self.config.target_path,
                    self.config.reach_output_file,
                )
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
                selected_alerts = select_diff_alerts(diff_report, strict_blocking=self.config.strict_blocking)
                filtered_alerts = filter_alerts_by_reachability(
                    selected_alerts,
                    sarif_reachability,
                    self.config.target_path,
                    self.config.reach_output_file,
                    logger=self.logger,
                    fallback_to_blocking_for_reachable=True,
                )
                selected_diff = clone_diff_with_selected_alerts(diff_report, filtered_alerts)

                # Generate the SARIF structure using Messages
                console_security_comment = Messages.create_security_comment_sarif(selected_diff)
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
        if not sbom_file_name:
            return

        sbom_data = getattr(diff_report, "sbom", None)
        if sbom_data is None:
            sbom_data = []

        self.write_json_file(sbom_file_name, sbom_data)

    def build_summary_text(self, diff_report: Diff) -> str:
        """Render the console summary text for stdout and file output."""
        selected_alerts = select_diff_alerts(diff_report, strict_blocking=self.config.strict_blocking)
        has_new_alerts = len(selected_alerts) > 0
        has_unchanged_alerts = (
            self.config.strict_blocking and
            hasattr(diff_report, 'unchanged_alerts') and
            len(diff_report.unchanged_alerts) > 0
        )

        if not has_new_alerts and not has_unchanged_alerts:
            return "No issues found"

        new_blocking = sum(1 for issue in diff_report.new_alerts if issue.error)
        new_warning = sum(1 for issue in diff_report.new_alerts if issue.warn)

        unchanged_blocking = 0
        unchanged_warning = 0
        if has_unchanged_alerts:
            unchanged_blocking = sum(1 for issue in diff_report.unchanged_alerts if issue.error)
            unchanged_warning = sum(1 for issue in diff_report.unchanged_alerts if issue.warn)

        selected_diff = clone_diff_with_selected_alerts(diff_report, selected_alerts)
        console_security_comment = Messages.create_console_security_alert_table(selected_diff)

        lines = ["Security issues detected by Socket Security:"]
        if new_blocking > 0:
            lines.append(f"  - NEW blocking issues: {new_blocking}")
        if new_warning > 0:
            lines.append(f"  - NEW warning issues: {new_warning}")
        if unchanged_blocking > 0:
            lines.append(
                f"  - EXISTING blocking issues: {unchanged_blocking} (causing failure due to --strict-blocking)"
            )
        if unchanged_warning > 0:
            lines.append(f"  - EXISTING warning issues: {unchanged_warning}")

        report_link = getattr(diff_report, "report_url", "") or getattr(diff_report, "diff_url", "")
        lines.append(f"Diff Url: {report_link}")
        lines.append("")
        lines.append(str(console_security_comment))
        return "\n".join(lines)

    def build_json_report(self, diff_report: Diff) -> dict:
        """Build the JSON report payload for stdout and file output."""
        selected_alerts = select_diff_alerts(diff_report, strict_blocking=self.config.strict_blocking)
        selected_diff = clone_diff_with_selected_alerts(diff_report, selected_alerts)
        report = Messages.create_security_comment_json(selected_diff)
        legal_flag = getattr(self.config, "legal", False)
        repo = getattr(self.config, "repo", None)
        branch = getattr(self.config, "branch", None)
        commit_sha = getattr(self.config, "commit_sha", None)
        report["report_url"] = getattr(diff_report, "report_url", None)
        report["repo"] = repo if isinstance(repo, str) or repo is None else None
        report["branch"] = branch if isinstance(branch, str) or branch is None else None
        report["commit_sha"] = commit_sha if isinstance(commit_sha, str) or commit_sha is None else None
        report["legal_mode"] = legal_flag if isinstance(legal_flag, bool) else False
        return report

    def save_json_file(self, diff_report: Diff, json_file_name: Optional[str] = None) -> None:
        if not json_file_name:
            return
        self.write_json_file(json_file_name, self.build_json_report(diff_report))

    def save_summary_file(self, diff_report: Diff, summary_file_name: Optional[str] = None) -> None:
        if not summary_file_name:
            return
        self.write_text_file(summary_file_name, self.build_summary_text(diff_report) + "\n")

    def save_report_link_file(self, diff_report: Diff, report_link_file_name: Optional[str] = None) -> None:
        if not report_link_file_name:
            return
        report_link = getattr(diff_report, "report_url", "") or getattr(diff_report, "diff_url", "")
        if not report_link:
            return
        self.write_text_file(report_link_file_name, report_link + "\n")

    def write_json_file(self, file_name: str, content: Any) -> None:
        file_path = Path(file_name)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(content, f, indent=2)

    def write_text_file(self, file_name: str, content: str) -> None:
        file_path = Path(file_name)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w") as f:
            f.write(content)

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
