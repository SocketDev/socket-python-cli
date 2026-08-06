#!/usr/bin/env bash
# Exits 0 when the reachability facts file contains components with alerts.
#
# Used by the e2e workflow's retry-probe hook: a --reach run against the
# known-vulnerable fixture that reports success but yields no alerted
# components is the signature of a transient tier-1 backend failure,
# so the run is worth repeating before validation fails the job.
set -euo pipefail

TARGET="${1:?usage: reach-facts-probe.sh <target-path>}"

uv run python - "$TARGET" <<'PY'
import sys

from socketsecurity.core.alert_selection import load_components_with_alerts

components = load_components_with_alerts(sys.argv[1], ".socket.facts.json")
sys.exit(0 if components else 1)
PY
