import pytest
from socketsecurity.core import Core
from socketsecurity.core.classes import Issue


class TestDiffAlerts:
    """Test alert collection for diff reports"""

    def test_get_unchanged_alerts_filters_errors(self):
        """Test that get_unchanged_alerts only returns error/warn alerts"""
        alerts_dict = {
            'alert1': [
                Issue(error=True, warn=False, purl='npm/pkg1', type='malicious'),
                Issue(error=False, warn=False, purl='npm/pkg1', type='info', monitor=True)
            ],
            'alert2': [
                Issue(error=False, warn=True, purl='npm/pkg2', type='typosquat')
            ]
        }

        result = Core.get_unchanged_alerts(alerts_dict)

        # Should only include error=True and warn=True alerts
        assert len(result) == 2
        assert any(alert.error for alert in result)
        assert any(alert.warn for alert in result)
        assert not any(alert.monitor and not (alert.error or alert.warn) for alert in result)

    def test_get_unchanged_alerts_deduplicates(self):
        """Test that get_unchanged_alerts deduplicates by purl+type"""
        alerts_dict = {
            'alert1': [
                Issue(error=True, warn=False, purl='npm/pkg1', type='malicious'),
                Issue(error=True, warn=False, purl='npm/pkg1', type='malicious')  # Duplicate
            ]
        }

        result = Core.get_unchanged_alerts(alerts_dict)

        # Should deduplicate
        assert len(result) == 1

    def test_get_unchanged_alerts_empty(self):
        """Test that get_unchanged_alerts handles empty input"""
        result = Core.get_unchanged_alerts({})
        assert len(result) == 0

    def test_get_removed_alerts_all_alerts(self):
        """Test that get_removed_alerts returns all alerts from removed packages"""
        alerts_dict = {
            'alert1': [
                Issue(error=True, warn=False, purl='npm/pkg1', type='malicious'),
                Issue(error=False, warn=True, purl='npm/pkg1', type='typosquat')
            ]
        }

        result = Core.get_removed_alerts(alerts_dict)

        # Should include all alerts, not just error/warn
        assert len(result) == 2

    def test_get_removed_alerts_deduplicates(self):
        """Test that get_removed_alerts deduplicates by purl+type"""
        alerts_dict = {
            'alert1': [
                Issue(error=True, warn=False, purl='npm/pkg1', type='malicious'),
                Issue(error=True, warn=False, purl='npm/pkg1', type='malicious')  # Duplicate
            ]
        }

        result = Core.get_removed_alerts(alerts_dict)

        # Should deduplicate
        assert len(result) == 1

    def test_get_removed_alerts_empty(self):
        """Test that get_removed_alerts handles empty input"""
        result = Core.get_removed_alerts({})
        assert len(result) == 0
