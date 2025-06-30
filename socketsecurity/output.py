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
        if self.config.enable_json:
            self.output_console_json(diff_report, self.config.sbom_file)
        elif self.config.enable_sarif:
            self.output_console_sarif(diff_report, self.config.sbom_file)
        else:
            self.output_console_comments(diff_report, self.config.sbom_file)
        if self.config.jira_plugin.enabled:
            jira_config = {
                "enabled": self.config.jira_plugin.enabled,
                "levels": self.config.jira_plugin.levels or [],
                **(self.config.jira_plugin.config or {})
            }
            plugin_mgr = PluginManager({"jira": jira_config})
            plugin_mgr.send(diff_report, config=self.config)

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
        if len(diff_report.new_alerts) == 0:
            self.logger.info("No issues found")
            return

        console_security_comment = Messages.create_console_security_alert_table(diff_report)
        self.logger.info("Security issues detected by Socket Security:")
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
        if not diff_report.new_alerts:
            return True

        if self.config.disable_blocking:
            return True

        return not any(issue.error for issue in diff_report.new_alerts)

    def save_sbom_file(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Saves SBOM file if filename is provided"""
        if not sbom_file_name or not diff_report.sbom:
            return

        sbom_path = Path(sbom_file_name)
        sbom_path.parent.mkdir(parents=True, exist_ok=True)

        with open(sbom_path, "w") as f:
            json.dump(diff_report.sbom, f, indent=2)

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
