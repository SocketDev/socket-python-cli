from copy import deepcopy
from dataclasses import dataclass
from typing import Optional

from socketsecurity.config import CliConfig
from socketsecurity.core.alert_selection import (
    clone_diff_with_selected_alerts,
    select_diff_alerts,
)
from socketsecurity.core.classes import Diff, Purl
from socketsecurity.core.messages import Messages
from socketsecurity.core.report_urls import build_alert_links


@dataclass(frozen=True)
class ReportReferences:
    full_scan_id: str
    report_url: Optional[str]
    diff_url: Optional[str]
    is_full_scan: bool
    diff_scan_id: Optional[str] = None
    old_scan_id: Optional[str] = None
    new_scan_id: Optional[str] = None
    old_scan_url: Optional[str] = None
    new_scan_url: Optional[str] = None

    def console_link(self) -> Optional[tuple[str, str]]:
        if self.is_full_scan:
            if self.report_url:
                return "Report Url", self.report_url
            if self.diff_url:
                return "Report Url", self.diff_url
        else:
            if self.diff_url:
                return "Diff Url", self.diff_url
            if self.report_url:
                return "Report Url", self.report_url
        return None


def build_report_references(diff_report: Diff) -> ReportReferences:
    return ReportReferences(
        full_scan_id=getattr(diff_report, "id", ""),
        report_url=getattr(diff_report, "report_url", None),
        diff_url=getattr(diff_report, "diff_url", ""),
        is_full_scan=getattr(diff_report, "is_full_scan", False),
        diff_scan_id=getattr(diff_report, "diff_scan_id", None),
        old_scan_id=getattr(diff_report, "old_scan_id", None),
        new_scan_id=getattr(diff_report, "new_scan_id", None),
        old_scan_url=getattr(diff_report, "old_scan_url", None),
        new_scan_url=getattr(diff_report, "new_scan_url", None),
    )


def _serialize_package_change(package: Purl) -> dict[str, object]:
    result = deepcopy(package.to_dict())
    result["scores"] = deepcopy(package.scores)
    return result


def build_console_summary(diff_report: Diff, config: CliConfig) -> str:
    references = build_report_references(diff_report)
    is_full_scan = references.is_full_scan
    link = references.console_link()

    if is_full_scan and not getattr(diff_report, "alerts_fetched", False):
        lines = ["Full scan completed. Findings were not fetched for console output."]
        if link:
            lines.append(f"{link[0]}: {link[1]}")
        return "\n".join(lines)

    selected_alerts = select_diff_alerts(
        diff_report,
        strict_blocking=config.strict_blocking,
    )
    has_new_alerts = len(selected_alerts) > 0
    has_unchanged_alerts = (
        config.strict_blocking
        and hasattr(diff_report, "unchanged_alerts")
        and len(diff_report.unchanged_alerts) > 0
    )

    if not has_new_alerts and not has_unchanged_alerts:
        if link:
            return f"No issues found\n{link[0]}: {link[1]}"
        return "No issues found"

    new_blocking = sum(1 for issue in diff_report.new_alerts if issue.error)
    new_warning = sum(1 for issue in diff_report.new_alerts if issue.warn)

    unchanged_blocking = 0
    unchanged_warning = 0
    if has_unchanged_alerts:
        unchanged_blocking = sum(
            1 for issue in diff_report.unchanged_alerts if issue.error
        )
        unchanged_warning = sum(
            1 for issue in diff_report.unchanged_alerts if issue.warn
        )

    selected_diff = clone_diff_with_selected_alerts(diff_report, selected_alerts)
    console_security_comment = Messages.create_console_security_alert_table(
        selected_diff
    )

    blocking_label = "Blocking issues" if is_full_scan else "NEW blocking issues"
    warning_label = "Warning issues" if is_full_scan else "NEW warning issues"

    lines = ["Security issues detected by Socket Security:"]
    if new_blocking > 0:
        lines.append(f"  - {blocking_label}: {new_blocking}")
    if new_warning > 0:
        lines.append(f"  - {warning_label}: {new_warning}")
    if unchanged_blocking > 0:
        lines.append(
            f"  - EXISTING blocking issues: {unchanged_blocking} "
            "(causing failure due to --strict-blocking)"
        )
    if unchanged_warning > 0:
        lines.append(f"  - EXISTING warning issues: {unchanged_warning}")
    if is_full_scan:
        lines.append(
            "  Reported against the whole repository, with no baseline to compare "
            "against, so these do not affect the exit code."
        )

    if link:
        lines.append(f"{link[0]}: {link[1]}")
    lines.append("")
    lines.append(str(console_security_comment))
    return "\n".join(lines)


def build_socket_json_report(
    diff_report: Diff,
    config: CliConfig,
) -> dict[str, object]:
    references = build_report_references(diff_report)
    selected_alerts = select_diff_alerts(
        diff_report,
        strict_blocking=config.strict_blocking,
    )
    selected_diff = clone_diff_with_selected_alerts(diff_report, selected_alerts)
    report = Messages.create_security_comment_json(selected_diff)
    for alert_row in report["new_alerts"]:
        package_url = alert_row.get("url")
        alert_type = alert_row.get("type")
        links = build_alert_links(
            package_url if isinstance(package_url, str) else None,
            alert_type if isinstance(alert_type, str) else None,
        )
        alert_row["package_url"] = links.package_url
        alert_row["info_url"] = links.info_url
    legal_flag = getattr(config, "legal", False)
    repo = getattr(config, "repo", None)
    branch = getattr(config, "branch", None)
    commit_sha = getattr(config, "commit_sha", None)
    report["full_scan_id"] = references.full_scan_id
    report["diff_url"] = references.diff_url
    report["report_url"] = references.report_url
    report["diff_scan_id"] = references.diff_scan_id
    report["old_scan_id"] = references.old_scan_id
    report["new_scan_id"] = references.new_scan_id
    report["old_scan_url"] = references.old_scan_url
    report["new_scan_url"] = references.new_scan_url
    report["repo"] = repo if isinstance(repo, str) or repo is None else None
    report["branch"] = branch if isinstance(branch, str) or branch is None else None
    report["commit_sha"] = (
        commit_sha if isinstance(commit_sha, str) or commit_sha is None else None
    )
    report["legal_mode"] = legal_flag if isinstance(legal_flag, bool) else False
    report["new_packages"] = [
        _serialize_package_change(package) for package in diff_report.new_packages
    ]
    report["updated_packages"] = [
        _serialize_package_change(package) for package in diff_report.updated_packages
    ]
    report["removed_packages"] = [
        _serialize_package_change(package) for package in diff_report.removed_packages
    ]
    report["replaced_packages"] = [
        _serialize_package_change(package) for package in diff_report.replaced_packages
    ]
    return report
