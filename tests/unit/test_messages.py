from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.messages import Messages


def _issue(**kwargs):
    values = {
        "pkg_type": "npm",
        "pkg_name": "example-lib",
        "pkg_version": "1.4.2",
        "type": "highCVE",
        "severity": "high",
        "title": "High CVE",
        "description": "A vulnerable dependency.",
        "suggestion": "Upgrade to a patched release.",
        "purl": "pkg:npm/example-lib@1.4.2",
        "url": "https://socket.dev/npm/package/example-lib/overview/1.4.2",
        "manifests": "package-lock.json",
        "introduced_by": [["example-lib", "package-lock.json"]],
        "error": True,
    }
    values.update(kwargs)
    return Issue(**values)


def test_console_security_alert_table_includes_patched_version():
    diff = Diff(
        new_alerts=[
            _issue(props={"firstPatchedVersionIdentifier": "1.5.0"}),
        ]
    )

    table = Messages.create_console_security_alert_table(diff)

    assert table.field_names == [
        "Alert",
        "Package",
        "Patched Version",
        "url",
        "Introduced by",
        "Manifest File",
        "CI Status",
    ]
    assert table.rows[0][2] == "1.5.0"


def test_console_security_alert_table_leaves_missing_patched_version_blank():
    diff = Diff(
        new_alerts=[
            _issue(),
            _issue(props={}),
            _issue(props={"firstPatchedVersionIdentifier": None}),
        ]
    )

    table = Messages.create_console_security_alert_table(diff)

    assert [row[2] for row in table.rows] == ["", "", ""]


def test_security_comment_includes_patched_version_when_available():
    diff = Diff(
        new_alerts=[
            _issue(props={"firstPatchedVersionIdentifier": "1.5.0"}),
        ],
        diff_url="https://socket.dev/dashboard/org/acme/diff/before/after",
    )

    comment = Messages.security_comment_template(diff)

    assert "<strong>Patched version:</strong> <code>1.5.0</code>" in comment


def test_security_comment_omits_missing_patched_version():
    diff = Diff(
        new_alerts=[_issue(props={})],
        diff_url="https://socket.dev/dashboard/org/acme/diff/before/after",
    )

    comment = Messages.security_comment_template(diff)

    assert "Patched version:" not in comment
