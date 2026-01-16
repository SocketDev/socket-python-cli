import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from .core.messages import Messages
from .core.classes import Diff, Issue
from .config import CliConfig
from socketsecurity.plugins.manager import PluginManager
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
            self.logger.debug("=== Slack Webhook Debug Information ===")
            self.logger.debug(f"Slack Plugin Enabled: {self.config.slack_plugin.enabled}")
            self.logger.debug(f"SOCKET_SLACK_ENABLED environment variable: {slack_enabled_env}")
            self.logger.debug(f"SOCKET_SLACK_CONFIG_JSON environment variable: {slack_config_env}")
            self.logger.debug(f"Slack Webhook URL: {slack_url}")
            self.logger.debug(f"Slack Alert Levels: {self.config.slack_plugin.levels}")
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
        """
        if diff_report.id != "NO_DIFF_RAN":
            # Generate the SARIF structure using Messages
            console_security_comment = Messages.create_security_comment_sarif(diff_report)
            self.save_sbom_file(diff_report, sbom_file_name)
            # Print the SARIF output to the console in JSON format
            print(json.dumps(console_security_comment, indent=2))

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
