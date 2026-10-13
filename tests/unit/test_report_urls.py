from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.diff_result import matching_full_scan_url, normalize_report_url
from socketsecurity.core.messages import Messages
from socketsecurity.core.report_urls import add_query_params, build_alert_links
from socketsecurity.plugins.jira import JiraPlugin
from socketsecurity.plugins.slack import SlackPlugin


def test_alert_link_projection_preserves_package_url_and_encodes_type_segment():
    package_url = "https://packages.example.test/@scope/pkg?view=a&mode=b#source"
    assert build_alert_links(package_url, "envVars").package_url == package_url
    assert build_alert_links(package_url, "envVars").info_url == (
        "https://socket.dev/alerts/envVars"
    )
    assert build_alert_links(package_url, "highCVE").info_url == (
        "https://socket.dev/alerts/highCVE"
    )
    assert build_alert_links(None, None).package_url is None
    assert build_alert_links(None, None).info_url is None
    assert build_alert_links("", "").package_url is None
    assert build_alert_links("", "").info_url is None
    assert build_alert_links("https://pkg.example/a", "odd/type?#").info_url == (
        "https://socket.dev/alerts/odd%2Ftype%3F%23"
    )


def _security_issue(
    alert_type: str | None,
    package_url: str | None,
    *,
    package_name: str = "sample",
) -> Issue:
    return Issue(
        pkg_name=package_name,
        pkg_version="1.0.0",
        pkg_type="npm",
        type=alert_type,
        severity="high",
        title="Fixture finding",
        description="Fixture description",
        suggestion="Upgrade",
        purl="pkg:npm/identifier-only@1.0.0",
        url=package_url,
        manifests="package.json",
        introduced_by=[],
        error=True,
        props={},
    )


def test_security_comment_uses_package_and_type_documentation_links():
    issue = _security_issue(
        "envVars",
        'https://packages.example.test/@scope/pkg?view="a"&mode=b',
    )
    comment = Messages.security_comment_template(
        Diff(new_alerts=[issue], report_url="https://reports.example.test/scan")
    )

    assert (
        '<a href="https://packages.example.test/@scope/pkg?view=&quot;a&quot;&amp;mode=b">This package</a>'
        in comment
    )
    assert (
        '<a href="https://socket.dev/alerts/envVars">About this alert type</a>'
        in comment
    )
    assert "pkg:npm/identifier-only@1.0.0" not in comment
    assert "alerts/malware" not in comment
    assert "What is known malware?" not in comment
    assert "This alert</a>" not in comment
    assert "start-socket-alert-sample" in comment
    assert "package.json" in comment
    assert "View full report" in comment

    malware_comment = Messages.security_comment_template(
        Diff(new_alerts=[_security_issue("malware", "https://pkg.example.test/a")])
    )
    assert (
        '<a href="https://socket.dev/alerts/malware">About this alert type</a>'
        in malware_comment
    )
    assert "What is known malware?" not in malware_comment


def test_security_comment_license_and_missing_alert_links():
    license_issue = _security_issue(
        "licenseSpdxDisj",
        "https://packages.example.test/license",
        package_name="licensed-package",
    )
    license_comment = Messages.security_comment_template(
        Diff(new_alerts=[license_issue])
    )
    assert (
        '<a href="https://packages.example.test/license">This package</a>'
        in license_comment
    )
    assert (
        '<a href="https://socket.dev/alerts/licenseSpdxDisj">About this alert type</a>'
        in license_comment
    )

    comment = Messages.security_comment_template(
        Diff(
            new_alerts=[
                _security_issue(None, "https://pkg.example.test/no-type"),
                _security_issue("envVars", None, package_name="no-package-url"),
                _security_issue(None, None, package_name="no-links"),
            ]
        )
    )
    assert '<a href="https://pkg.example.test/no-type">This package</a>' in comment
    assert (
        '<a href="https://socket.dev/alerts/envVars">About this alert type</a>'
        in comment
    )
    assert " | </p>" not in comment
    assert comment.count("ℹ️ Read more on:") == 2
    assert all(
        'href=""' not in line
        for line in comment.splitlines()
        if "Read more on:" in line
    )

    missing_package_url = _security_issue("envVars", None, package_name="missing-url")
    del missing_package_url.url
    missing_url_comment = Messages.security_comment_template(
        Diff(new_alerts=[missing_package_url])
    )
    assert (
        '<a href="https://socket.dev/alerts/envVars">About this alert type</a>'
        in missing_url_comment
    )
    assert "This package</a>" not in missing_url_comment


def test_url_normalization_and_nested_scan_identity():
    assert normalize_report_url(" https://report.invalid/a?q=1#part ") == (
        " https://report.invalid/a?q=1#part "
    )
    assert normalize_report_url(None) is None
    assert normalize_report_url("") is None
    assert normalize_report_url(42) is None
    assert matching_full_scan_url(
        {"id": "expected", "html_url": "https://report.invalid/scan"},
        "expected",
    ) == "https://report.invalid/scan"
    assert matching_full_scan_url(
        {"id": "other", "html_url": "https://report.invalid/scan"},
        "expected",
    ) is None
    assert matching_full_scan_url(
        {"id": "expected", "html_url": None}, "expected"
    ) is None
    assert matching_full_scan_url([], "expected") is None


def test_query_addition_preserves_unrelated_pairs_and_fragment():
    assert add_query_params(
        "https://reports.invalid/path?keep=a%2Fb&keep=two&action=old#section",
        {"action": "error,warn", "file": "folder/name file.txt"},
    ) == (
        "https://reports.invalid/path?keep=a%2Fb&keep=two&action=error%2Cwarn&"
        "file=folder%2Fname+file.txt#section"
    )
    assert add_query_params("https://reports.invalid/path#fragment", {"tab": "files"}) == (
        "https://reports.invalid/path?tab=files#fragment"
    )
    assert add_query_params(None, {"tab": "files"}) is None
    assert add_query_params("", {"tab": "files"}) is None
    assert add_query_params("https://[malformed", {"tab": "files"}) == (
        "https://[malformed"
    )


def test_manifest_and_report_links_handle_query_and_missing_urls():
    diff = Diff(report_url="https://reports.invalid/scan?keep=yes#details")
    manifest = Messages.get_manifest_file_url(diff, "folder/a b.txt")
    assert manifest == (
        "https://reports.invalid/scan?keep=yes&tab=files&file=folder%2Fa+b.txt#details"
    )
    assert Messages.get_manifest_file_url(Diff(), "folder/a.txt") == ""

    alert_diff = Diff(
        diff_url="https://reports.invalid/diff?keep=yes#details",
        report_url="https://reports.invalid/report",
        new_alerts=[],
    )
    assert Messages.get_view_report_url(alert_diff) == (
        "https://reports.invalid/diff?keep=yes#details"
    )
    alert_diff.diff_url = None
    assert Messages.get_view_report_url(alert_diff) == "https://reports.invalid/report"
    alert_diff.report_url = None
    assert Messages.get_view_report_url(alert_diff) == ""


def test_slack_and_jira_report_consumers_fall_back_or_omit_links():
    linked_diff = Diff(
        report_url="https://reports.invalid/report",
        diff_url=None,
    )
    blocks = SlackPlugin.create_slack_blocks_from_diff(
        linked_diff, CliConfig(api_token="fixture", repo="fixture/repo")
    )
    assert "<https://reports.invalid/report|scan>" in blocks[0]["text"]["text"]
    paragraph = JiraPlugin.create_adf_paragraph(linked_diff)
    assert paragraph["content"][2]["marks"][0]["attrs"]["href"] == (
        "https://reports.invalid/report"
    )

    missing_diff = Diff(report_url=None, diff_url=None)
    blocks_without_link = SlackPlugin.create_slack_blocks_from_diff(
        missing_diff, CliConfig(api_token="fixture", repo="fixture/repo")
    )
    assert "<|scan>" not in blocks_without_link[0]["text"]["text"]
    assert "this *scan*" in blocks_without_link[0]["text"]["text"]
    paragraph_without_link = JiraPlugin.create_adf_paragraph(missing_diff)
    assert paragraph_without_link["content"][2] == {
        "type": "text",
        "text": "View Socket Security scan results",
    }


def test_alert_comment_uses_query_safe_report_link_and_omits_absence():
    issue = Issue(
        pkg_name="sample",
        pkg_version="1.0.0",
        pkg_type="npm",
        type="malware",
        severity="high",
        title="Finding",
        description="Description",
        suggestion="Upgrade",
        purl="pkg:npm/sample@1.0.0",
        url="https://alerts.invalid/finding",
        manifests="package.json",
        introduced_by=[],
        error=True,
    )
    diff = Diff(
        new_alerts=[issue],
        report_url="https://reports.invalid/scan?keep=yes#details",
        diff_url=None,
    )

    comment = Messages.security_comment_template(diff)

    assert (
        "[View full report](https://reports.invalid/scan?keep=yes&action=error%2Cwarn#details)"
        in comment
    )
    diff.report_url = None
    comment_without_link = Messages.security_comment_template(diff)
    assert "View full report" not in comment_without_link
    assert "(None" not in comment_without_link
