# Changelog

## 2.3.0

### Breaking change: exit codes for infrastructure errors

API and infrastructure errors (timeouts, network failures, unexpected exceptions)
now exit with code `3` instead of `1`. Exit code `1` is now exclusively used for
blocking security findings.

`--disable-blocking` no longer zeroes out infrastructure errors -- it only affects
exit code `1` (security findings). If your pipeline relied on `--disable-blocking`
to also swallow infra errors, use `--exit-code-on-api-error 0` instead.

If you have pipeline logic that checks `exit_code == 1` to catch any CLI failure,
update it to handle `3` separately for infrastructure errors. See the exit code
reference in the README.

### New: `--exit-code-on-api-error`

New flag to remap the infrastructure error exit code. Useful for Buildkite
`soft_fail` configs or pipelines with existing exit-code conventions:

```
socketcli --exit-code-on-api-error 100 ...
```

Set to `0` to swallow infrastructure errors entirely.

### New: commit message auto-truncation

`--commit-message` values longer than 200 characters are now automatically
truncated before being sent to the API. This prevents HTTP 413 errors from
oversized URL query parameters -- common when using AI-generated commit
messages or piping in `$BUILDKITE_MESSAGE`.

### Improved: Buildkite log formatting

When running inside a Buildkite job (`BUILDKITE=true`), infrastructure errors
now emit Buildkite log section markers (`^^^ +++` and `--- :warning:`) so the
error section auto-expands in the Buildkite UI, along with a tip on using
`soft_fail` to prevent blocking.

### Dependencies

Bundles eight Dependabot main-app upgrades (closes #175, #177, #181, #184, #188,
#190, #198, #200) and three e2e fixture upgrades (closes #186, #187, #196).
All target versions verified through Socket Firewall (`sfw`).

### CI / Internal

- New `.github/dependabot.yml` with grouped weekly bumps and a 7-day cooldown;
  e2e fixtures are intentionally excluded.
- New `dependabot-review` workflow runs Socket Firewall install smoke jobs on
  every Dependabot PR -- no API secret required.
- `python-tests` workflow now runs `uv lock --locked` drift check, a top-level
  import smoke step, and `pip-audit`.
- `e2e-test` workflow skips on Dependabot PRs (which can't access secrets);
  Socket Firewall covers the supply-chain check.

## 2.2.87

- Fixed diff scan API requests so `--timeout` is passed through to the Socket SDK request layer.
- Fixed `--exclude-license-details` so the full-scan diff comparison request sends `include_license_details=false`.
- Let diff comparison API failures propagate to top-level CLI exit handling so `--disable-blocking` is honored consistently.

## 2.2.83

- Fixed branch detection in detached-HEAD CI checkouts. When `git name-rev --name-only HEAD` returned an output with a suffix operator (e.g. `remotes/origin/master~1`, `master^0`), the `~N`/`^N` was previously passed through as the branch name and rejected by the Socket API as an invalid Git ref. The suffix is now stripped before the prefix split, producing the bare branch name.

## 2.2.71

- Added `strace` to the Docker image for debugging purposes.

## 2.2.70

- Set the scan to `'socket_tier1'` when using the `--reach` flag. This ensures Tier 1 scans are properly integrated into the organization-wide alerts.

## 2.2.69

- Added `--reach-enable-analysis-splitting` flag to enable analysis splitting (disabled by default).
- Added `--reach-detailed-analysis-log-file` flag to print detailed analysis log file path.
- Added `--reach-lazy-mode` flag to enable lazy mode for reachability analysis.
- Changed default behavior: analysis splitting is now disabled by default. The old `--reach-disable-analysis-splitting` flag is kept as a hidden no-op for backwards compatibility.

## 2.2.64

- Included PyPy in the Docker image.

## 2.2.57

- Fixed Dockerfile to set `GOROOT` to `/usr/lib/go` when using system Go (`GO_VERSION=system`) instead of always using `/usr/local/go`.

## 2.2.56

- Removed process timeout from reachability analysis subprocess. Timeouts are now only passed to the Coana CLI via the `--analysis-timeout` flag.
