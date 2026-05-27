#!/usr/bin/env bash
set -euo pipefail

LOG="/tmp/e2e-output.log"

# 1. Verify reachability analysis completed
if grep -q "Reachability analysis completed successfully" "$LOG"; then
  echo "PASS: Reachability analysis completed"
  grep "Reachability analysis completed successfully" "$LOG"
  grep "Results written to:" "$LOG" || true
else
  echo "FAIL: Reachability analysis did not complete successfully"
  cat "$LOG"
  exit 1
fi

# 2. Verify scan produced a report URL
if grep -q "Full scan report URL: https://socket.dev/" "$LOG"; then
  echo "PASS: Full scan report URL found"
  grep "Full scan report URL:" "$LOG"
elif grep -q "Diff Url: https://socket.dev/" "$LOG"; then
  echo "PASS: Diff URL found"
  grep "Diff Url:" "$LOG"
else
  echo "FAIL: No report URL found in scan output"
  cat "$LOG"
  exit 1
fi

FACTS_PATH="tests/e2e/fixtures/simple-npm/.socket.facts.json"
if [ ! -f "$FACTS_PATH" ]; then
  echo "FAIL: Expected reachability facts at $FACTS_PATH after initial scan"
  exit 1
fi
echo "PASS: Reachability facts file present at $FACTS_PATH"

# 3-4. Build SARIF from the facts file produced by the initial --reach run.
# Avoid re-running reach + full scan here; duplicate API scans are slow and flaky in CI.
uv run python -c "
import json
from pathlib import Path

from socketsecurity.core.alert_selection import load_components_with_alerts
from socketsecurity.core.messages import Messages

target = 'tests/e2e/fixtures/simple-npm'
facts_file = '.socket.facts.json'
components = load_components_with_alerts(target, facts_file)
if not components:
    raise SystemExit('FAIL: no components with alerts in .socket.facts.json')

for outfile, reach_filter in [
    ('/tmp/sarif-all.sarif', 'all'),
    ('/tmp/sarif-reachable.sarif', 'reachable'),
]:
    sarif = Messages.create_security_comment_sarif_from_facts(
        components,
        reachability_filter=reach_filter,
        grouping='instance',
    )
    Path(outfile).write_text(json.dumps(sarif, indent=2))
    count = len(sarif['runs'][0]['results'])
    print(f'PASS: Wrote {outfile} ({count} results, filter={reach_filter})')
"

# 5. Verify reachable-only results are a subset of all results
test -f /tmp/sarif-all.sarif
test -f /tmp/sarif-reachable.sarif

uv run python -c "
import json
with open('/tmp/sarif-all.sarif') as f:
    all_data = json.load(f)
with open('/tmp/sarif-reachable.sarif') as f:
    reach_data = json.load(f)
all_count = len(all_data['runs'][0]['results'])
reach_count = len(reach_data['runs'][0]['results'])
print(f'All results: {all_count}, Reachable-only results: {reach_count}')
assert reach_count <= all_count, f'FAIL: reachable ({reach_count}) > all ({all_count})'
print('PASS: Reachable-only results is a subset of all results')
"
