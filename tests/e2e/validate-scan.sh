#!/usr/bin/env bash
set -euo pipefail

LOG="/tmp/e2e-output.log"

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
