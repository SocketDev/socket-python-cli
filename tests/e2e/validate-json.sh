#!/usr/bin/env bash
set -euo pipefail

LOG="/tmp/e2e-output.log"

python3 -c "
import json, sys

# The JSON output is on stdout; the log may also contain stderr debug lines.
# Find the first line that parses as valid JSON.
found = False
with open('$LOG') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                found = True
                print(f'PASS: Valid JSON output with {len(data)} top-level key(s)')
                break
        except json.JSONDecodeError:
            continue

if not found:
    print('FAIL: No valid JSON object found in output')
    sys.exit(1)
"
