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

# 3. Run SARIF with --sarif-reachability all
socketcli \
  --target-path tests/e2e/fixtures/simple-npm \
  --reach \
  --sarif-file /tmp/sarif-all.sarif \
  --sarif-scope full \
  --sarif-reachability all \
  --disable-blocking \
  2>/dev/null

# 4. Run SARIF with --sarif-reachability reachable (filtered)
socketcli \
  --target-path tests/e2e/fixtures/simple-npm \
  --reach \
  --sarif-file /tmp/sarif-reachable.sarif \
  --sarif-scope full \
  --sarif-reachability reachable \
  --disable-blocking \
  2>/dev/null

# 5. Verify reachable-only results are a subset of all results
test -f /tmp/sarif-all.sarif
test -f /tmp/sarif-reachable.sarif

python3 -c "
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
