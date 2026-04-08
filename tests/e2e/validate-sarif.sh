#!/usr/bin/env bash
set -euo pipefail

SARIF="/tmp/results.sarif"

if [ ! -f "$SARIF" ]; then
  echo "FAIL: SARIF file not found at $SARIF"
  exit 1
fi

python3 -c "
import json, sys
with open('$SARIF') as f:
    data = json.load(f)
assert data['version'] == '2.1.0', f'Invalid version: {data[\"version\"]}'
assert '\$schema' in data, 'Missing \$schema'
count = len(data['runs'][0]['results'])
print(f'PASS: Valid SARIF 2.1.0 with {count} result(s)')
"
