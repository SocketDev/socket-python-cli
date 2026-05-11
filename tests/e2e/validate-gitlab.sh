#!/usr/bin/env bash
set -euo pipefail

REPORT="gl-dependency-scanning-report.json"

if [ ! -f "$REPORT" ]; then
  echo "FAIL: GitLab report not found at $REPORT"
  exit 1
fi

python3 -c "
import json, re, sys

with open('$REPORT') as f:
    data = json.load(f)

errors = []

# v15.0.0 required root-level keys
for key in ('version', 'scan', 'vulnerabilities', 'dependency_files'):
    if key not in data:
        errors.append(f'Missing required root key: {key}')

if 'scan' in data:
    scan = data['scan']

    # Timestamp format: YYYY-MM-DDTHH:MM:SS (no microseconds, no trailing Z)
    ts_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$')
    for field in ('start_time', 'end_time'):
        val = scan.get(field, '')
        if not ts_pattern.match(val):
            errors.append(f'scan.{field} \"{val}\" does not match pattern YYYY-MM-DDTHH:MM:SS')

    if scan.get('type') != 'dependency_scanning':
        errors.append(f'scan.type is \"{scan.get(\"type\")}\" expected \"dependency_scanning\"')

    analyzer_id = scan.get('analyzer', {}).get('id', '')
    if analyzer_id != 'socket-security':
        errors.append(f'scan.analyzer.id is \"{analyzer_id}\" expected \"socket-security\"')

    scanner_id = scan.get('scanner', {}).get('id', '')
    if scanner_id != 'socket-cli':
        errors.append(f'scan.scanner.id is \"{scanner_id}\" expected \"socket-cli\"')

    if scan.get('status') != 'success':
        errors.append(f'scan.status is \"{scan.get(\"status\")}\" expected \"success\"')

# dependency_files structure check
if 'dependency_files' in data:
    for i, df in enumerate(data['dependency_files']):
        for req in ('path', 'package_manager', 'dependencies'):
            if req not in df:
                errors.append(f'dependency_files[{i}] missing required key: {req}')

if errors:
    for e in errors:
        print(f'FAIL: {e}')
    sys.exit(1)

vuln_count = len(data.get('vulnerabilities', []))
dep_file_count = len(data.get('dependency_files', []))
print(f'PASS: Valid GitLab v15.0.0 report with {vuln_count} vulnerability(ies) and {dep_file_count} dependency file(s)')
"
