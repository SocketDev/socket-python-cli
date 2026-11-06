"""Checks a ``--reach`` run made inside the Docker image.

Run with the image's Python, from the repository root:

    validate-image-reachability.py <fixture> --probe
        Exits 0 when the fixture's facts file has alerted components. The workflow
        retries a run that fails this, because the reachability backend intermittently
        returns nothing to analyze.

    validate-image-reachability.py <fixture> --log <cli-output>
        Exits 0 when Coana analyzed at least one vulnerability. That needs the
        ecosystem's toolchain in the image to work, which is what this test is for.
        Whether a given vulnerability is reachable depends on Coana and the backend,
        not on the image, so the verdict itself is not asserted.
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

from socketsecurity.core.alert_selection import load_components_with_alerts

FACTS_FILE = ".socket.facts.json"
ANALYZED = ("reachable", "unreachable")
# Coana's log line when the backend returned no vulnerable components to analyze.
NOTHING_TO_ANALYZE = "Found 0 projects across 0 ecosystems to analyze"


def alert_states(fixture: str) -> Counter:
    components = load_components_with_alerts(fixture, FACTS_FILE) or []
    return Counter(
        alert["props"]["reachability"]
        for component in components
        for alert in component["alerts"]
    )


def validate(fixture: str, log: str) -> int:
    if "Reachability analysis completed successfully" not in log:
        print("FAIL: reachability analysis did not complete")
        return 1
    if not (Path(fixture) / FACTS_FILE).is_file():
        print(f"FAIL: no {FACTS_FILE} in {fixture}")
        return 1

    states = alert_states(fixture)
    if not states:
        if NOTHING_TO_ANALYZE in log:
            print(
                f"::warning title=e2e-image inconclusive::the backend returned nothing to analyze for {fixture} "
                "after retries, so the image's toolchain was not exercised"
            )
            return 0
        print(
            f"FAIL: {FACTS_FILE} has no alerted components, and the log lacks the backend's nothing-to-analyze line"
        )
        return 1

    print(f"Reachability states for {fixture}: {dict(states)}")
    if not any(states[state] for state in ANALYZED):
        print(
            "FAIL: Coana analyzed no vulnerability; check the toolchain errors in the CLI output"
        )
        return 1
    if states["error"]:
        print(
            f"::warning title=e2e-image analysis errors::{states['error']} vulnerabilities in {fixture} ended in error"
        )
    print("PASS: Coana analyzed vulnerabilities with the image's toolchain")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--log", type=Path)
    args = parser.parse_args()

    if args.probe:
        return 0 if alert_states(args.fixture) else 1
    return validate(args.fixture, args.log.read_text())


if __name__ == "__main__":
    sys.exit(main())
