# Changelog

## 2.3.0

### New: `--exit-code-on-api-error`

Adds a configurable exit code for API / infrastructure failures (timeouts,
network errors, unexpected exceptions), so CI pipelines can distinguish them
from blocking security findings (exit `1`):

```
socketcli --exit-code-on-api-error 100 ...
```

Default is `3` (the code the CLI already used for these errors), so **default
behavior is unchanged** — the exit code only changes when you pass the flag.
Set it to a Buildkite `soft_fail` code, or to `0` to swallow infra errors.

**Interaction to be aware of:** `--disable-blocking` forces exit `0` for *all*
outcomes and therefore overrides `--exit-code-on-api-error`. Use the new flag
*without* `--disable-blocking` if you want a custom infra-error code to take
effect. See the exit-code reference in the README.

> A future `3.0` release is planned to make infrastructure errors exit non-zero
> even under `--disable-blocking` (so outages stop being silently swallowed).
> That is a breaking change and is intentionally **not** in this release.

### New: commit message auto-truncation

`--commit-message` values longer than 200 characters are now automatically
truncated before being sent to the API, preventing HTTP 413 errors from
oversized URL query parameters (common with AI-generated commit messages or
`$BUILDKITE_MESSAGE`).

### Improved: Buildkite log formatting

When running inside a Buildkite job (`BUILDKITE=true`), infrastructure errors
emit Buildkite log section markers (`^^^ +++` / `--- :warning:`) so the error
section auto-expands in the BK UI, plus a `soft_fail` hint. No effect on other
CI platforms.

### Fixed

- `--timeout` is now honored end-to-end: it was only applied to the local
  `CliClient`, but the full-scan diff comparison uses the Socket SDK instance,
  which was constructed without the CLI timeout and defaulted to 1200s.
- `--exclude-license-details` now propagates to the full-scan diff comparison
  request (it was only applied to full-scan params / report URLs before).

## 2.2.90

- Migrated license enrichment PURL lookup to the org-scoped endpoint (`POST /v0/orgs/{slug}/purl`) from the deprecated global endpoint (`POST /v0/purl`).

## 2.2.83

- Fixed branch detection in detached-HEAD CI checkouts. When `git name-rev --name-only HEAD` returned an output with a suffix operator (e.g. `remotes/origin/master~1`, `master^0`), the `~N`/`^N` was previously passed through as the branch name and rejected by the Socket API as an invalid Git ref. The suffix is now stripped before the prefix split, producing the bare branch name.

## 2.2.80

- Hardened GitHub Actions workflows.
- Fixed broken links on PyPI page.

## 2.2.79

- Updated minimum required Python version.
- Tweaked CI checks.

## 2.2.78

- Fixed reachability filtering.
- Added config file support.

## 2.2.77

- Fixed `has_manifest_files` failing to match root-level manifest files.

## 2.2.76

- Added SARIF file output support.
- Improved reachability filtering.

## 2.2.75

- Fixed `workspace` flag regression by updating SDK dependency.

## 2.2.74

- Added `--workspace` flag to CLI args.
- Added GitLab branch protection flag.
- Added e2e tests for full scans and full scans with reachability.
- Bumped dependencies: `cryptography`, `virtualenv`, `filelock`, `urllib3`.

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
