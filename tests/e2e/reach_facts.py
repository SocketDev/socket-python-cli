"""Reads a ``--reach`` run's facts file and CLI output for the e2e workflows.

reach_facts.py <fixture> --probe
    Exits 0 when the fixture's facts file has alerted components. A run that
    fails this is retried, because the reachability backend intermittently
    returns nothing to analyze while the CLI reports success.

reach_facts.py <fixture> --inconclusive <cli-output>
    Exits 0 when the output shows that known backend result: a manifest was
    uploaded, the backend's components were all orphaned, and Coana found
    nothing to analyze. After retries, that result is a warning, not a failure.

reach_facts.py <fixture> --validate-analyzed <cli-output>
    Exits 0 when the run completed and Coana reached a reachable or unreachable
    verdict for at least one vulnerability, which needs the ecosystem's
    toolchain to work, or when the output shows the inconclusive backend
    result above. Which verdict depends on Coana and the backend, so it is not
    asserted.
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

from socketsecurity.core.alert_selection import load_components_with_alerts

FACTS_FILE = ".socket.facts.json"
ANALYZED = ("reachable", "unreachable")
NOTHING_TO_ANALYZE = (
    re.compile(r"Found [1-9]\d* manifest files? for reachability upload"),
    re.compile(r"Found 0 projects across 0 ecosystems to analyze"),
    re.compile(r"Filtered out \d+ orphaned components?"),
)


def alert_states(fixture: str) -> Counter:
    components = load_components_with_alerts(fixture, FACTS_FILE) or []
    return Counter(alert["props"]["reachability"] for component in components for alert in component["alerts"])


def nothing_to_analyze(log: str) -> bool:
    return all(pattern.search(log) for pattern in NOTHING_TO_ANALYZE)


def validate_analyzed(fixture: str, log: str) -> bool:
    if "Reachability analysis completed successfully" not in log:
        print(f"FAIL: reachability analysis did not complete for {fixture}")
        return False
    if not (Path(fixture) / FACTS_FILE).is_file():
        print(f"FAIL: no {FACTS_FILE} in {fixture}")
        return False

    states = alert_states(fixture)
    if not states:
        if nothing_to_analyze(log):
            print(
                f"::warning title=reachability inconclusive::the backend returned nothing to analyze for {fixture} "
                "after retries, so the toolchain was not exercised"
            )
            return True
        print(
            f"FAIL: {FACTS_FILE} in {fixture} has no alerted components, and the output lacks the known backend result"
        )
        return False

    print(f"Reachability states for {fixture}: {dict(states)}")
    if states["error"]:
        print(
            f"::warning title=reachability analysis errors::{states['error']} vulnerabilities in {fixture} ended in error"
        )
    if not any(states[state] for state in ANALYZED):
        print(f"FAIL: Coana analyzed no vulnerability in {fixture}; check the toolchain errors in the CLI output")
        return False
    print(f"PASS: Coana analyzed vulnerabilities in {fixture}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--inconclusive", type=Path, metavar="CLI_OUTPUT")
    mode.add_argument("--validate-analyzed", type=Path, metavar="CLI_OUTPUT")
    args = parser.parse_args()

    if args.probe:
        return 0 if alert_states(args.fixture) else 1
    if args.inconclusive:
        return 0 if nothing_to_analyze(args.inconclusive.read_text()) else 1
    return 0 if validate_analyzed(args.fixture, args.validate_analyzed.read_text()) else 1


if __name__ == "__main__":
    sys.exit(main())
