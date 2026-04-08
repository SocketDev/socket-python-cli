#!/usr/bin/env bash
set -euo pipefail

LOG="/tmp/e2e-output.log"

python3 -c "
import json, sys

# The JSON output may be prefixed with a logger timestamp (e.g. '2026-04-08 22:46:50,580: {...}').
# Try parsing the full line first, then from the first '{' character.
found = False
with open('$LOG') as f:
    for line in f:
        line = line.strip()
        if not line or '{' not in line:
            continue
        # Try full line first, then from the first brace
        for candidate in (line, line[line.index('{'):]):
            try:
                data = json.loads(candidate)
                if isinstance(data, dict):
                    found = True
                    print(f'PASS: Valid JSON output with {len(data)} top-level key(s)')
                    break
            except json.JSONDecodeError:
                continue
        if found:
            break

if not found:
    print('FAIL: No valid JSON object found in output')
    sys.exit(1)
"
