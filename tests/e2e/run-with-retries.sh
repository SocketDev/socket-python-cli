#!/usr/bin/env bash
# Runs a CLI command and retries it while a completeness probe fails.
#
#   run-with-retries.sh <label> <probe> <command...>
#
# The command's output goes to /tmp/e2e-output.log. <probe> is a shell command
# that exits 0 when the output looks complete; when it is empty, the command
# runs once. The reachability backend intermittently returns nothing to analyze
# while the CLI reports success, so a run that fails the probe is repeated, up to
# three attempts. A result that stays incomplete is left for validation to
# classify, and sets diagnostics=true in $GITHUB_OUTPUT so the job uploads its
# files. Retries are warning annotations, so flake frequency stays visible.
set -uo pipefail

label="$1"
probe="$2"
shift 2

max_attempts=3
attempt=1
while :; do
  "$@" 2>&1 | tee /tmp/e2e-output.log || exit
  [ -z "$probe" ] && break
  if bash -c "$probe"; then
    break
  fi
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "::warning title=${label} incomplete results::output still fails the completeness probe after ${max_attempts} attempts; letting validation classify the result"
    echo "diagnostics=true" >> "${GITHUB_OUTPUT:-/dev/null}"
    break
  fi
  echo "::warning title=${label} transient retry::attempt ${attempt} failed the completeness probe (suspected backend transient); retrying"
  echo "${label}: retry after attempt ${attempt} — completeness probe failed (suspected transient)" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  attempt=$((attempt+1))
  sleep 30
done
