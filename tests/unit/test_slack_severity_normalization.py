"""The Slack formatter keys on "medium"; the API sends "middle".

Every severity lookup in ``socketsecurity/plugins/formatters/slack.py`` is keyed
on ``medium``, but ``middle`` is what the API actually emits -- it is the value
in the OpenAPI spec's ``SocketIssueSeverity`` and in the SDK enum. Unnormalized,
a mid-severity finding fell through every one of them at once:

* it was not counted, so the summary always read ``Medium: 0``
* it was excluded from ``total_findings``, which can drive ``omitted_count``
  negative when mid-severity findings are the ones being displayed
* it sorted at the default order of 4, below ``low``, so it was truncated out of
  the message first when the block limit was reached

Two other call sites already handle both spellings (``Messages.map_socket_
severity_to_gitlab`` and the GitLab severity map); this formatter did not.
"""

import unittest

from socketsecurity.plugins.formatters.slack import (
    SEVERITY_EMOJI,
    SEVERITY_ORDER,
    _extract_alert_info,
    format_socket_facts_for_slack,
)


def _component(severity: str) -> dict:
    return {
        "name": "example-package",
        "version": "1.0.0",
        "alerts": [{"title": "Example alert", "severity": severity, "props": {}}],
    }


class TestSeverityNormalization(unittest.TestCase):
    def test_middle_normalizes_to_medium(self):
        info = _extract_alert_info(_component("middle"), {"severity": "middle"})
        self.assertEqual(info["severity"], "medium")

    def test_middle_gets_the_medium_order_not_the_default(self):
        info = _extract_alert_info(_component("middle"), {"severity": "middle"})
        self.assertEqual(info["severity_order"], SEVERITY_ORDER["medium"])
        # Regression: the default of 4 sorted mid-severity below "low".
        self.assertLess(info["severity_order"], SEVERITY_ORDER["low"])

    def test_middle_gets_the_medium_emoji_not_the_fallback(self):
        info = _extract_alert_info(_component("middle"), {"severity": "middle"})
        self.assertEqual(info["severity_emoji"], SEVERITY_EMOJI["medium"])
        self.assertNotEqual(info["severity_emoji"], SEVERITY_EMOJI["low"])

    def test_medium_still_works(self):
        info = _extract_alert_info(_component("medium"), {"severity": "medium"})
        self.assertEqual(info["severity"], "medium")
        self.assertEqual(info["severity_order"], SEVERITY_ORDER["medium"])

    def test_middle_findings_are_counted_in_the_summary(self):
        result = format_socket_facts_for_slack([_component("middle")])
        self.assertEqual(len(result), 1)
        self.assertIn("🟡 Medium: 1", result[0]["summary"])

    def test_middle_findings_reach_total_findings(self):
        # Regression: excluded from the total, omitted_count could go negative.
        result = format_socket_facts_for_slack([_component("middle")])
        self.assertEqual(result[0]["total_findings"], 1)

    def test_unrecognized_severity_still_falls_back(self):
        info = _extract_alert_info(
            _component("brand-new-level"), {"severity": "brand-new-level"}
        )
        self.assertEqual(info["severity_order"], 4)
        self.assertEqual(info["severity_emoji"], "⚪")


if __name__ == "__main__":
    unittest.main()
