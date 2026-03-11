import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

from socketsecurity.core.classes import Diff, Issue
from socketsecurity.plugins.slack import SlackPlugin


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
        introduced_by=[("dep", "package.json")],
        url="https://socket.dev/test",
        props={"ghsaId": ghsa_id},
    )


def test_slack_diff_alerts_include_unchanged_when_strict_blocking():
    plugin = SlackPlugin({
        "enabled": True,
        "mode": "webhook",
        "url": "https://hooks.slack.com/services/test",
        "url_configs": {"default": {}},
    })
    cfg = SimpleNamespace(
        repo="example-repo",
        reach=False,
        strict_blocking=True,
        enable_debug=False,
        target_path=".",
        reach_output_file=".socket.facts.json",
    )

    diff = Diff()
    diff.new_alerts = [_issue("new-pkg", "GHSA-AAAA-BBBB-CCCC", error=True)]
    diff.unchanged_alerts = [_issue("old-pkg", "GHSA-DDDD-EEEE-FFFF", error=True)]

    captured_titles = []

    def _capture(diff_arg, _config):
        captured_titles.extend([a.title for a in diff_arg.new_alerts])
        return [{"type": "section", "text": {"type": "mrkdwn", "text": "ok"}}]

    with patch.object(SlackPlugin, "create_slack_blocks_from_diff", side_effect=_capture), \
         patch("socketsecurity.plugins.slack.requests.post") as mock_post:
        mock_post.return_value = Mock(status_code=200, text="ok")
        plugin._send_webhook_alerts(diff, cfg)

    assert "Vuln in new-pkg" in captured_titles
    assert "Vuln in old-pkg" in captured_titles


def test_slack_reachability_alerts_only_uses_facts_reachability(tmp_path):
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
                "name": "unreachable-pkg",
                "version": "1.0.0",
                "vulnerabilities": [{"ghsaId": "GHSA-DDDD-EEEE-FFFF", "severity": "HIGH"}],
                "reachability": [{
                    "ghsa_id": "GHSA-DDDD-EEEE-FFFF",
                    "reachability": [{"type": "unreachable"}],
                }],
            },
        ],
    }), encoding="utf-8")

    plugin = SlackPlugin({
        "enabled": True,
        "mode": "webhook",
        "url": "https://hooks.slack.com/services/test",
        "url_configs": {"default": {"reachability_alerts_only": True}},
    })
    cfg = SimpleNamespace(
        repo="example-repo",
        reach=True,
        strict_blocking=True,
        enable_debug=False,
        target_path=str(tmp_path),
        reach_output_file=".socket.facts.json",
    )

    diff = Diff()
    # Strict mode should include unchanged alert set before reachability filtering.
    diff.new_alerts = [_issue("unreachable-pkg", "GHSA-DDDD-EEEE-FFFF", error=True)]
    diff.unchanged_alerts = [_issue("reachable-pkg", "GHSA-AAAA-BBBB-CCCC", error=False)]

    captured_titles = []

    def _capture(diff_arg, _config):
        captured_titles.extend([a.title for a in diff_arg.new_alerts])
        return [{"type": "section", "text": {"type": "mrkdwn", "text": "ok"}}]

    with patch.object(SlackPlugin, "create_slack_blocks_from_diff", side_effect=_capture), \
         patch.object(SlackPlugin, "_send_reachability_alerts"), \
         patch("socketsecurity.plugins.slack.requests.post") as mock_post:
        mock_post.return_value = Mock(status_code=200, text="ok")
        plugin._send_webhook_alerts(diff, cfg)

    assert captured_titles == ["Vuln in reachable-pkg"]
