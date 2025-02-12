import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from .core.messages import Messages
from .core.classes import Diff, Issue


class OutputHandler:
    blocking_disabled: bool
    logger: logging.Logger

    def __init__(self, blocking_disabled: bool):
        self.blocking_disabled = blocking_disabled
        self.logger = logging.getLogger("socketcli")

    def handle_output(self, diff_report: Diff, sbom_file_name: Optional[str] = None, json_output: bool = False) -> int:
        """Main output handler that determines output format and returns exit code"""
        if json_output:
            self.output_console_json(diff_report, sbom_file_name)
        else:
            self.output_console_comments(diff_report, sbom_file_name)

        self.save_sbom_file(diff_report, sbom_file_name)
    
    def return_exit_code(self, diff_report: Diff) -> int:
        if not self.report_pass(diff_report) and not self.blocking_disabled:
            return 1
        elif len(diff_report.new_alerts) > 0 and not self.blocking_disabled:
            # 5 means warning alerts but no blocking alerts
            return 5
        else:
            return 0

    def output_console_comments(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Outputs formatted console comments"""
        if len(diff_report.new_alerts) == 0:
            self.logger.info("No issues found")
            return

        console_security_comment = Messages.create_console_security_alert_table(diff_report)
        self.logger.info("Security issues detected by Socket Security:")
        self.logger.info(console_security_comment)

    def output_console_json(self, diff_report: Diff, sbom_file_name: Optional[str] = None) -> None:
        """Outputs JSON formatted results"""
        console_security_comment = Messages.create_security_comment_json(diff_report)
        self.logger.info(json.dumps(console_security_comment))


    def report_pass(self, diff_report: Diff) -> bool:
        """Determines if the report passes security checks"""
        if not diff_report.new_alerts:
            return True

        if self.blocking_disabled:
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
