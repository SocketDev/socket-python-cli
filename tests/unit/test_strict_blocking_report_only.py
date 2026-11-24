"""Existing alerts under ``--strict-blocking --disable-blocking`` are listed, not failed on.

Report-only pipelines run with both flags so the PR comment and console show existing
alerts. Neither may claim those alerts fail the run when the exit code stays 0.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.messages import Messages
from socketsecurity.output import OutputHandler


def _issue(name, error=True, warn=False):
    return Issue(
        pkg_type="npm",
        pkg_name=name,
        pkg_version="1.0.0",
        purl=f"{name}@1.0.0",
        type="malware",
        severity="critical",
        title="Known malware",
        description="Bad.",
        suggestion="Remove it.",
        url=f"https://socket.dev/npm/package/{name}",
        props={},
        key=f"key-{name}",
        error=error,
        warn=warn,
    )


def _diff(existing):
    diff = Diff()
    diff.new_alerts = []
    diff.unchanged_alerts = list(existing)
    diff.diff_url = "https://socket.dev/diff"
    diff.report_url = "https://socket.dev/report"
    return diff


def _comment(existing, disable_blocking):
    config = SimpleNamespace(
        strict_blocking=True, disable_blocking=disable_blocking, disable_ignore=False, scm="github"
    )
    return Messages.security_comment_template(_diff(existing), config)


def _summary(existing, disable_blocking):
    config = Mock(spec=CliConfig)
    config.strict_blocking = True
    config.disable_blocking = disable_blocking
    return OutputHandler(config, Mock()).build_summary_text(_diff(existing))


def test_comment_says_blocking_existing_alerts_fail_the_run():
    comment = _comment([_issue("delta"), _issue("gamma", error=False, warn=True)], disable_blocking=False)

    assert "`--strict-blocking` fails the run on the 1 with a **Block** action." in comment


@pytest.mark.parametrize("count, verb", [(1, "has"), (2, "have")])
def test_comment_does_not_claim_a_failure_under_disable_blocking(count, verb):
    comment = _comment([_issue(f"pkg{i}") for i in range(count)], disable_blocking=True)

    assert "fails the run" not in comment
    assert f"{count} {verb} a **Block** action but don't fail the run" in comment
    assert "`--disable-blocking` is set" in comment


def test_comment_with_only_warnings_says_they_do_not_fail_the_run():
    comment = _comment([_issue("gamma", error=False, warn=True)], disable_blocking=False)

    assert "None has a **Block** action, so they don't fail the run." in comment
    assert "fails the run on" not in comment


@pytest.mark.parametrize("disable_blocking, reason", [
    (False, "causing failure due to --strict-blocking"),
    (True, "not failing the run: --disable-blocking is set"),
])
def test_console_summary_states_whether_existing_blockers_fail_the_run(disable_blocking, reason):
    summary = _summary([_issue("delta")], disable_blocking)

    assert f"EXISTING blocking issues: 1 ({reason})" in summary
