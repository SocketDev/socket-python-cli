"""Repeat sightings of one finding collapse into one alert; distinct advisories don't.

The same alert arrives once per manifest that pulls a package in, so the diff
collapses alerts on Issue.consolidation_key. Every CVE of one severity on a
package shares an alert type, so the key has to include the advisory ID, or a
package's second advisory is dropped along with any blocking action it carries.
"""
from unittest.mock import Mock

import pytest

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.messages import Messages
from socketsecurity.output import OutputHandler


def _cve(advisory, error=False, warn=False, pkg_type="npm", key=None, props_field="ghsaId"):
    return Issue(
        pkg_type=pkg_type,
        pkg_name="lodash",
        pkg_version="4.17.20",
        purl="lodash@4.17.20",
        type="criticalCVE",
        severity="critical",
        title="Critical CVE",
        description="A vulnerability.",
        suggestion="Upgrade.",
        url="https://socket.dev/npm/package/lodash",
        key=key or f"key-{advisory}",
        props={props_field: advisory},
        error=error,
        warn=warn,
    )


def test_two_advisories_on_one_package_are_both_new_alerts():
    alerts = {
        "k1": [_cve("GHSA-aaaa-aaaa-aaaa", error=True)],
        "k2": [_cve("GHSA-bbbb-bbbb-bbbb", error=True)],
    }

    new_alerts = Core.get_new_alerts(alerts, {})

    assert sorted(a.advisory_id() for a in new_alerts) == [
        "GHSA-AAAA-AAAA-AAAA",
        "GHSA-BBBB-BBBB-BBBB",
    ]


def test_blocking_advisory_is_not_hidden_behind_a_warning():
    """The kept advisory is a warning; dropping the second would pass the run."""
    alerts = {
        "k1": [_cve("GHSA-aaaa-aaaa-aaaa", warn=True)],
        "k2": [_cve("GHSA-bbbb-bbbb-bbbb", error=True)],
    }
    diff = Diff()
    diff.new_alerts = Core.get_new_alerts(alerts, {})

    config = Mock(spec=CliConfig)
    config.disable_blocking = False
    config.strict_blocking = False
    assert not OutputHandler(config, Mock()).report_pass(diff)


def test_same_advisory_from_two_manifests_is_one_alert():
    alerts = {
        "k1": [_cve("GHSA-aaaa-aaaa-aaaa", error=True), _cve("GHSA-aaaa-aaaa-aaaa", error=True)],
    }

    assert len(Core.get_new_alerts(alerts, {})) == 1


def test_unchanged_and_removed_alerts_keep_each_advisory():
    alerts = {
        "k1": [_cve("CVE-2026-0001", error=True, props_field="cveId")],
        "k2": [_cve("CVE-2026-0002", error=True, props_field="cveId")],
    }

    assert len(Core.get_unchanged_alerts(alerts)) == 2
    assert len(Core.get_removed_alerts(alerts)) == 2


def test_consolidation_key_includes_ecosystem_and_ignores_advisory_case():
    npm = _cve("ghsa-aaaa-aaaa-aaaa")
    pypi = _cve("GHSA-AAAA-AAAA-AAAA", pkg_type="pypi")

    assert npm.consolidation_key() != pypi.consolidation_key()
    assert npm.consolidation_key()[3] == pypi.consolidation_key()[3]


def test_adding_a_cve_to_a_ghsa_record_keeps_the_same_finding_identity():
    ghsa_only = _cve("GHSA-aaaa-aaaa-aaaa", error=True)
    both = _cve("GHSA-aaaa-aaaa-aaaa", error=True)
    both.props["cveId"] = "CVE-2026-0001"

    assert ghsa_only.consolidation_key() == both.consolidation_key()
    assert Messages.generate_uuid_from_alert_gitlab(ghsa_only) == Messages.generate_uuid_from_alert_gitlab(both)
    assert len(Core.get_new_alerts({ghsa_only.key: [ghsa_only, both]}, {})) == 1


@pytest.mark.parametrize("ghsa_field", ["ghsaId", "ghsa_id"])
@pytest.mark.parametrize("cve_field", ["cveId", "cve_id", "cve"])
def test_disjoint_advisory_ids_are_not_assumed_to_be_aliases(ghsa_field, cve_field):
    # Neither input establishes whether these identifiers name the same advisory.
    # Retaining both protects a blocker from being hidden behind another finding.
    ghsa_only = _cve("GHSA-aaaa-aaaa-aaaa", warn=True, props_field=ghsa_field)
    cve_only = _cve("CVE-2026-0001", error=True, props_field=cve_field)

    alerts = Core.get_new_alerts({ghsa_only.key: [ghsa_only], cve_only.key: [cve_only]}, {})

    assert alerts == [ghsa_only, cve_only]
    report = Messages.create_security_comment_gitlab(Diff(new_alerts=alerts))
    assert len({finding["id"] for finding in report["vulnerabilities"]}) == 2
    config = Mock(spec=CliConfig, disable_blocking=False, strict_blocking=False)
    assert OutputHandler(config, Mock()).return_exit_code(Diff(new_alerts=alerts)) == 1


def test_non_advisory_alerts_still_collapse_per_package_and_type():
    """Alerts with no advisory ID keep the per-package, per-type collapse."""
    first = Issue(pkg_type="npm", purl="a@1.0.0", type="envVars", props={}, warn=True, key="k1")
    second = Issue(pkg_type="npm", purl="a@1.0.0", type="envVars", props={}, warn=True, key="k2")

    assert len(Core.get_new_alerts({"k1": [first], "k2": [second]}, {})) == 1


def test_pr_comment_rows_name_the_advisory():
    diff = Diff()
    diff.new_alerts = [_cve("GHSA-aaaa-aaaa-aaaa", error=True), _cve("GHSA-bbbb-bbbb-bbbb", error=True)]
    diff.diff_url = "https://socket.dev/diff"
    diff.report_url = "https://socket.dev/report"

    comment = Messages.security_comment_template(diff)

    assert "Critical CVE (GHSA-AAAA-AAAA-AAAA)" in comment
    assert "Critical CVE (GHSA-BBBB-BBBB-BBBB)" in comment


def test_title_already_naming_the_advisory_is_left_alone():
    alert = _cve("GHSA-aaaa-aaaa-aaaa")
    alert.title = "GHSA-aaaa-aaaa-aaaa in lodash"

    assert Messages.alert_title_with_advisory(alert) == "GHSA-aaaa-aaaa-aaaa in lodash"


def test_gitlab_report_keeps_each_advisory_as_its_own_finding():
    diff = Diff()
    diff.new_alerts = [_cve("GHSA-aaaa-aaaa-aaaa", error=True), _cve("GHSA-bbbb-bbbb-bbbb", error=True)]

    report = Messages.create_security_comment_gitlab(diff)

    ids = [v["id"] for v in report["vulnerabilities"]]
    assert len(ids) == 2
    assert len(set(ids)) == 2


@pytest.mark.parametrize("advisory", ["", "GHSA-aaaa-aaaa-aaaa"])
@pytest.mark.parametrize("coordinates", [
    (("npm", "lodash@4.17.20"), ("pypi", "lodash@4.17.20")),
    (("maven", "org.first/lodash@4.17.20"), ("maven", "org.second/lodash@4.17.20")),
])
def test_gitlab_report_keeps_distinct_package_coordinates(advisory, coordinates):
    alerts = []
    for index, (ecosystem, purl) in enumerate(coordinates):
        alert = _cve(advisory, pkg_type=ecosystem)
        alert.purl = purl
        alert.manifests = f"manifest-{index}.json"
        alerts.append(alert)
    diff = Diff(new_alerts=alerts[:1], unchanged_alerts=alerts[1:])

    report = Messages.create_security_comment_gitlab(diff)

    ids = {v["id"] for v in report["vulnerabilities"]}
    assert len(ids) == 2
    assert {f["path"] for f in report["dependency_files"]} == {"manifest-0.json", "manifest-1.json"}
    # IDs remain stable if either package is the only one present next time.
    for alert in alerts:
        single = Messages.create_security_comment_gitlab(Diff(new_alerts=[alert]))
        assert single["vulnerabilities"][0]["id"] in ids


def test_gitlab_report_deduplicates_a_finding_listed_as_new_and_existing():
    first = _cve("GHSA-aaaa-aaaa-aaaa")
    repeat = _cve("GHSA-aaaa-aaaa-aaaa")
    diff = Diff(new_alerts=[first], unchanged_alerts=[repeat])

    report = Messages.create_security_comment_gitlab(diff)

    assert len(report["vulnerabilities"]) == 1


@pytest.mark.parametrize("purl", [
    "org.first/lodash@4.17.20", "maven/org.first/lodash@4.17.20",
    "pkg:maven/org.first/lodash@4.17.20",
])
def test_gitlab_ids_are_stable_across_full_scan_and_diff_purl_formats(purl):
    alert = _cve("GHSA-aaaa-aaaa-aaaa", pkg_type="maven")
    alert.purl = "org.first/lodash@4.17.20"
    expected = Messages.generate_uuid_from_alert_gitlab(alert)
    alert.purl = purl

    assert Messages.generate_uuid_from_alert_gitlab(alert) == expected


def test_gitlab_ids_for_findings_without_an_advisory_ignore_manifest_changes():
    alert = Issue(
        pkg_type="npm", pkg_name="a", pkg_version="1.0.0", purl="a@1.0.0",
        type="malware", severity="critical", props={}, manifests="package.json",
    )
    expected = Messages.generate_uuid_from_alert_gitlab(alert)
    alert.manifests = "nested/package.json"

    assert Messages.generate_uuid_from_alert_gitlab(alert) == expected
