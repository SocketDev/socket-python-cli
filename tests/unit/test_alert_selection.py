import json

from socketsecurity.core.alert_selection import (
    filter_alerts_by_reachability,
    select_diff_alerts,
)
from socketsecurity.core.classes import Diff, Issue


def _issue(pkg_name: str, ghsa_id: str, error: bool = False) -> Issue:
    return Issue(
        pkg_name=pkg_name,
        pkg_version="1.0.0",
        severity="high",
        title=f"Vuln in {pkg_name}",
        description="test",
        type="vulnerability",
        manifests="package.json",
        pkg_type="npm",
        key=f"key-{pkg_name}",
        purl=f"pkg:npm/{pkg_name}@1.0.0",
        error=error,
        props={"ghsaId": ghsa_id},
    )


def test_select_diff_alerts_uses_new_only_without_strict():
    diff = Diff()
    diff.new_alerts = [Issue(title="new")]
    diff.unchanged_alerts = [Issue(title="unchanged")]

    selected = select_diff_alerts(diff, strict_blocking=False)
    assert [a.title for a in selected] == ["new"]


def test_select_diff_alerts_includes_unchanged_with_strict():
    diff = Diff()
    diff.new_alerts = [Issue(title="new")]
    diff.unchanged_alerts = [Issue(title="unchanged")]

    selected = select_diff_alerts(diff, strict_blocking=True)
    assert {a.title for a in selected} == {"new", "unchanged"}


def test_filter_alerts_by_reachability_supports_reachability_selectors(tmp_path):
    facts_path = tmp_path / ".socket.facts.json"
    facts_path.write_text(json.dumps({
        "components": [
            {
                "type": "npm",
                "name": "reachable-pkg",
                "version": "1.0.0",
                "vulnerabilities": [{"ghsaId": "GHSA-AAAA-BBBB-CCCC", "severity": "HIGH"}],
                "reachability": [{
                    "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
                    "reachability": [{"type": "reachable"}],
                }],
            },
            {
                "type": "npm",
                "name": "potential-pkg",
                "version": "1.0.0",
                "vulnerabilities": [{"ghsaId": "GHSA-DDDD-EEEE-FFFF", "severity": "HIGH"}],
                "reachability": [{
                    "ghsa_id": "GHSA-DDDD-EEEE-FFFF",
                    "reachability": [{"type": "potentially_reachable"}],
                }],
            },
            {
                "type": "npm",
                "name": "unreachable-pkg",
                "version": "1.0.0",
                "vulnerabilities": [{"ghsaId": "GHSA-GGGG-HHHH-IIII", "severity": "HIGH"}],
                "reachability": [{
                    "ghsa_id": "GHSA-GGGG-HHHH-IIII",
                    "reachability": [{"type": "unreachable"}],
                }],
            },
        ],
    }), encoding="utf-8")

    alerts = [
        _issue("reachable-pkg", "GHSA-AAAA-BBBB-CCCC"),
        _issue("potential-pkg", "GHSA-DDDD-EEEE-FFFF"),
        _issue("unreachable-pkg", "GHSA-GGGG-HHHH-IIII"),
    ]

    reachable = filter_alerts_by_reachability(
        alerts, "reachable", str(tmp_path), ".socket.facts.json"
    )
    assert [a.pkg_name for a in reachable] == ["reachable-pkg"]

    potentially = filter_alerts_by_reachability(
        alerts, "potentially", str(tmp_path), ".socket.facts.json"
    )
    assert [a.pkg_name for a in potentially] == ["potential-pkg"]

    reachable_or_potentially = filter_alerts_by_reachability(
        alerts, "reachable-or-potentially", str(tmp_path), ".socket.facts.json"
    )
    assert {a.pkg_name for a in reachable_or_potentially} == {"reachable-pkg", "potential-pkg"}
