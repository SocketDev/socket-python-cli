# Changelog

## 2.4.15

### Changed: bump pinned @coana-tech/cli to 15.6.1

- Bumped the pinned reachability engine (`@coana-tech/cli`) from `15.5.9` to
  `15.6.1`. See the [Coana changelogs](https://docs.coana.tech/changelogs) for
  engine changes.

## 2.4.14

### Changed: bump pinned @coana-tech/cli to 15.5.9

- Bumped the pinned `@coana-tech/cli` version to `15.5.9` (previously `15.5.7`).

## 2.4.13

### Changed: reachability analysis types now use full names instead of "Tier 1/2/3"

- Reachability analysis types are referred to by their full names instead of the
  "Tier 1/2/3" numbering: **Full application reachability** (formerly Tier 1),
  **Precomputed reachability** (formerly Tier 2), and **Dependency reachability**
  (formerly Tier 3). This updates `--help` text, command output, log messages, and docs
  only — wire-format values such as the `socket_tier1` scan type are unchanged for
  backward compatibility. See the reachability section in `docs/cli-reference.md` for the
  old→new name mapping.
- Bumped the pinned `@coana-tech/cli` version to `15.5.7`.

## 2.4.12

### Changed: consolidated coana launcher env vars into `SOCKET_CLI_COANA_LAUNCHER`

- The reachability launcher is now tuned via a single `SOCKET_CLI_COANA_LAUNCHER`
  environment variable (mirroring the Socket Node CLI): `auto` (default when unset; try
  `npx` first, fall back to `npm install` + `node` on launcher-level failures),
  `npm-install` (skip `npx` entirely), or `npx` (never fall back). An unrecognized value
  logs a warning and behaves as `auto`.
- The legacy `SOCKET_CLI_COANA_FORCE_NPM_INSTALL` and `SOCKET_CLI_COANA_DISABLE_NPM_FALLBACK`
  variables remain supported for back-compat when `SOCKET_CLI_COANA_LAUNCHER` is unset, but
  are deprecated and no longer documented.

## 2.4.11

### Changed: units for `--reach-analysis-timeout` and `--reach-analysis-memory-limit`

- `--reach-analysis-timeout` now accepts a duration with an optional unit suffix — `s`, `m`
  or `h` (e.g. `90s`, `10m`, `1h`). `--reach-analysis-memory-limit` now accepts a size with an
  optional unit suffix — `MB` or `GB`, case-insensitive (e.g. `512MB`, `8GB`). The value is
  passed through verbatim to the reachability engine (`@coana-tech/cli`), which owns parsing
  and validation, so error messages come from a single source of truth.
- Backward compatible: a bare number is still accepted (seconds for the timeout, MB for the
  memory limit), exactly as before. This legacy form is no longer documented but keeps working.
- Bumped the pinned `@coana-tech/cli` version to `15.5.0`, which ships the unit parser.

## 2.4.10

### Added: opt directories back into manifest discovery via `--include-dirs`

- New `--include-dirs` flag (comma-separated directory names) that re-includes directories
  the CLI excludes from manifest discovery by default. The default exclude list
  (`node_modules`, `bower_components`, `jspm_packages`, `__pycache__`, `.venv`, `venv`,
  `build`, `dist`, `.tox`, `.mypy_cache`, `.pytest_cache`, `*.egg-info`, `vendor`) is a sane
  default, but some projects keep manifest files under those names — e.g. `build/requirements.txt`.
  Pass `--include-dirs build,dist` to scan them. Names are matched against any path segment,
  mirroring how the default exclude list is applied.
- `--include-module-folders` now functions as documented: it re-includes the JS/TS module
  folders (`node_modules`, `bower_components`, `jspm_packages`) as a group. Previously the
  flag was accepted but had no effect.

## 2.4.9

### Added: opt-in streaming log channel via `--upload-logs`

- New `--upload-logs` flag (default off). When set, each CLI invocation registers a run, reports a per-run status (`in_progress` / `success` / `failure` / `cancelled`), and uploads a transcript of its own log output to the Socket backend for that run, visible in the Socket admin views. The transcript is captured regardless of the local `--enable-debug` state; the existing terminal verbosity is unchanged.
- New `--no-upload-logs` flag (mutually exclusive with `--upload-logs`) explicitly opts the run out of uploading logs, even when an org-level override would otherwise enable it. Use this when you need a guaranteed no-upload guarantee (e.g. legal/consent reasons).
- The Socket backend can also force-enable streaming for specific orgs in the absence of an explicit opt-out. The feature is best-effort — registration or upload failures silently degrade and never block the scan.

## 2.4.8

### Fixed: retry transient full-scan upload failures

- The full-scan upload (`POST /orgs/<org>/full-scans`) now retries transient
  gateway/connection failures — HTTP 502/503/504/408, dropped or reset connections, and
  request timeouts — up to 3 total attempts with increasing waits (~10s, then ~30s, plus
  jitter). Such failures are intermittent and a retried upload almost always succeeds.
  In these failure modes the server never finished reading the request body, so no scan
  was created and a retry does not duplicate one; in the rare case where a gateway
  timeout races a request the server later completes, the extra scan is benign and
  superseded by the retried one (as if the CLI had run twice).
  Non-transient errors (400/401/403/404/429 and error payloads) are never retried. Each
  retry logs a warning explaining what failed and when the next attempt happens.
- Requires `socketdev>=3.3.0`: the SDK now records the HTTP status code on the exceptions
  it raises and owns the transient-vs-deterministic classification
  (`APIFailure.is_transient_error()`), so the CLI no longer parses status codes out of
  exception message text.

## 2.4.7

### Changed: pin @coana-tech/cli version; auto-update is now opt-in

- Reachability analysis now runs a fixed `@coana-tech/cli` version pinned to this CLI release
  (`15.3.24`) via `npx`, instead of silently pulling the latest published version on every run.
  Engine version changes now ride with the Socket Python CLI release (standard `pip` upgrade),
  giving advance notice of analysis-engine changes.
- The CLI no longer runs `npm install -g @coana-tech/cli`; an existing global install is left
  untouched (never auto-updated or downgraded).
- Opt into always-newest with `--reach-version latest`; pin an explicit version with
  `--reach-version <semver>` (unchanged).
- Runs the engine via `npx --yes --force` (the same flags the Socket Node CLI passes for
  coana); `--yes` skips npx's interactive install prompt so non-interactive/CI runs don't hang.
- Added an `npm install` + `node` fallback for when the `npx` launcher is missing or fails
  before the engine starts. The installed engine is cached per version for the process
  lifetime (installs once). Tunable via `SOCKET_CLI_COANA_FORCE_NPM_INSTALL` (use the fallback
  as the primary path) and `SOCKET_CLI_COANA_DISABLE_NPM_FALLBACK` (never fall back). `node` is
  now part of the up-front prerequisite check. Also strips `npm_package_*` env vars before
  spawning the engine to avoid `E2BIG` in large monorepos.

## 2.4.6

### Docs: reachability reference corrections

- Documented the `uv` and Enterprise-plan prerequisites the CLI enforces **before** running
  reachability (exit code 3 if unmet), and clarified that per-ecosystem build toolchains
  (JDK / .NET / Go / a compatible Python interpreter) are checked by the analysis engine at
  runtime, not pre-checked by the CLI.
- Corrected the `--reach-min-severity` values to `info, low, moderate, high, critical`.
- Documented the previously-undocumented reachability flags: `--reach-enable-analysis-splitting`,
  `--reach-detailed-analysis-log-file`, `--reach-lazy-mode`, and `--reach-use-only-pregenerated-sboms`.
- Clarified that `--only-facts-file` submits only the facts file when **creating** the full scan
  (it does not require a pre-existing scan).
- Documentation-only; no functional code changes.

## 2.4.5

### Changed: Bump required SDK version to `>=3.2.1`

- Picks up `socketdev 3.2.1`.
- No CLI logic changes.

## 2.4.4

### Changed: Bump required SDK version to `>=3.2.0`

- Picks up `socketdev 3.2.0`, which adds `OTHER = "other"` to `SocketCategory`
  so the backend's `other` alert category no longer trips the
  "Unknown SocketCategory" warning fallback (SDK PR #85).
- No CLI logic changes.

## 2.4.3

### Added: unified `--exclude-paths` for manifest discovery and reachability

- New `--exclude-paths` flag (comma-separated globs) that excludes matching paths from
  BOTH SCA manifest discovery and reachability analysis. Patterns are scan-root-relative
  anchored globs (`*` does not cross `/`, `**` does), matching the Node CLI's behavior.
- Pattern validation rejects unsupported forms (negation, absolute paths, `..` traversal,
  and match-everything patterns). Patterns may be supplied on the CLI as a comma-separated
  string or via a `--config` file list.
- `--reach-exclude-paths` is now deprecated in favor of `--exclude-paths`. It still works
  (and is unioned into the Coana `--exclude-dirs` argument) but is marked deprecated in
  `--help` and warns at runtime.

## 2.4.2

### Added: reachability flag and Coana environment alignment with the Node CLI

- New `--reach-disable-external-tool-checks` flag (passes `--disable-external-tool-checks`
  to the Coana CLI).
- New `--reach-debug` flag to enable Coana debug output (`--debug`) independently of the
  global `--enable-debug`.
- Node-style `--reach-analysis-timeout` and `--reach-analysis-memory-limit` are now the
  primary flag names; the previous `--reach-timeout` / `--reach-memory-limit` continue to
  work as hidden aliases.
- The Coana subprocess now receives `SOCKET_CLI_VERSION` and `SOCKET_CALLER_USER_AGENT` so
  calls are attributed to the Python CLI. Proxies continue to work via the inherited
  `HTTPS_PROXY` / `HTTP_PROXY` environment variables, which Coana reads itself.
- `SOCKET_REPO_NAME` / `SOCKET_BRANCH_NAME` are no longer forwarded to Coana when the repo
  and branch are the default sentinels, avoiding cross-run reachability cache-bucket
  collisions.
- Tier 1 reachability finalize now retries with exponential backoff instead of giving up on
  the first transient error.

## 2.4.1

### Added: pyenv in the Docker image

- The `socketdev/cli` Docker image now bundles [pyenv](https://github.com/pyenv/pyenv)
  (pinned to `v2.7.1`) along with the Alpine build dependencies needed to compile
  CPython from source, so the image can build/install arbitrary Python versions on
  demand.
- The CLI itself is unchanged — this release only affects the published Docker image.

## 2.4.0

### Changed: license details are no longer requested on the full-scan diff

- Full-scan diff requests now always set `include_license_details=false`, keeping
  large diff responses smaller and avoiding truncation crashes on large repos.
- Soft breaking change for flag-scripted use: `--exclude-license-details` still
  controls the dashboard report URL, but no longer affects the internal diff
  request. Its `--help` text has been updated to reflect the narrower scope.
- License artifact output is unchanged: `--generate-license` continues to fetch
  license details from the dedicated PURL endpoint.
- Requires `socketdev>=3.1.2`.

## 2.3.1

### New: brotli-compressed `.socket.facts.json` upload

The reachability facts file (`.socket.facts.json`) is now brotli-compressed before it is
uploaded as part of a full scan. The Socket API transparently decompresses any multipart
part named exactly `.socket.facts.json.br` and stores it as plain `.socket.facts.json`, so
the stored result is unchanged — but the on-the-wire payload shrinks dramatically (a
~262 MB facts file compresses to roughly 15–30 MB).

This fixes large tier‑1 reachability scans that previously failed when the uncompressed
facts file exceeded the API's per‑file upload size cap (surfaced to the CLI as an HTTP
4xx/“502”, leaving the scan stuck with no report).

Details:

- Compression happens at the upload boundary (`Core.create_full_scan`); the file on disk is
  left untouched, so local consumers (SARIF/JSON output, tier‑1 finalize, alert selection)
  continue to read the plain `.socket.facts.json`.
- Only a file whose basename is exactly `.socket.facts.json` is compressed (the API matches
  that exact name). A custom `--reach-output-file` name is uploaded uncompressed, as before.
- Empty baseline-scan placeholder files are not compressed.
- Compression never blocks an upload: if it fails for any reason it falls back to uploading
  the plain file, and a partially-written `.socket.facts.json.br` is removed rather than
  left behind in the target directory.
- Adds a `brotli` (CPython) / `brotlicffi` (PyPy) dependency.

## 2.3.0

### New: `--exit-code-on-api-error`

- Added `--exit-code-on-api-error` so CI can distinguish API / infrastructure
  failures from blocking security findings. The default remains `3`; the flag
  only changes behavior when set explicitly.
- `--disable-blocking` still takes precedence and exits `0` for all outcomes.

### New: commit message auto-truncation

- `--commit-message` values longer than 200 characters are now truncated before
  being sent to the API, preventing HTTP 413 errors from oversized query
  parameters.

### Improved: Buildkite log formatting

- Infrastructure errors now emit Buildkite log section markers when
  `BUILDKITE=true`, making those failures easier to find in Buildkite logs.

### Fixed

- `--timeout` is now honored end-to-end: it was only applied to the local
  `CliClient`, but the full-scan diff comparison uses the Socket SDK instance,
  which was constructed without the CLI timeout and defaulted to 1200s.
- `--exclude-license-details` now propagates to the full-scan diff comparison
  request (it was only applied to full-scan params / report URLs before).

## 2.2.93

- Bundled twelve Dependabot dependency updates: `urllib3`, `gitpython`, `python-dotenv`, `pytest`, `uv`, `cryptography`, `pygments`, `requests`, and `idna` (main app), plus `axios`, `requests`, and `flask` (e2e fixtures). `idna` 3.11 → 3.15 includes the fix for CVE-2026-45409.
- Added `.github/dependabot.yml` with grouped weekly updates, a 7-day cooldown, and e2e fixtures excluded.
- Added a `dependabot-review` workflow that runs Socket Firewall (`sfw`) install checks on Dependabot PRs with no API token required.
- Added a `uv.lock` drift check, an import smoke test, and `pip-audit` to the test workflow; skipped e2e tests on Dependabot PRs.
- Tidied `.gitignore` and backfilled missing CHANGELOG entries for `2.2.81`, `2.2.85`, `2.2.86`, `2.2.88`, `2.2.89`, `2.2.91`, and `2.2.92`.

## 2.2.92

- Fixed dependency-overview rendering for unmapped alert types: alert types the SDK
  has no metadata for now fall back to a humanized Title-Cased label (e.g.
  `gptDidYouMean` -> "Possible typosquat attack (GPT)", `SQLInjection` -> "SQL
  Injection") instead of surfacing the raw camelCase identifier.

## 2.2.91

- Added legal/compliance artifact presets (`--legal`) and FOSSA-compatible output
  shapes (`--legal-format fossa`) for license and SBOM reporting.

## 2.2.90

- Migrated license enrichment PURL lookup to the org-scoped endpoint (`POST /v0/orgs/{slug}/purl`) from the deprecated global endpoint (`POST /v0/purl`).

## 2.2.89

- Added `uv.lock` to the version-incrementation CI check so a `pyproject.toml` /
  `__init__.py` version bump without a matching lockfile sync no longer slips through.
- Updated the local Python pre-commit hook to keep `uv.lock` in sync with
  `pyproject.toml` and `socketsecurity/__init__.py` version changes automatically.

## 2.2.88

- Added `bun.lock`, `bun.lockb`, and `vlt-lock.json` to the recognized manifest files
  for Socket scanning, with matching unit-test coverage.

## 2.2.86

- Bumped `socketdev` to `>=3.0.33,<4.0.0` to pick up the SDK fix for unknown alert
  categories (the SDK previously crashed while deserializing diff alerts when the API
  returned a category like `"other"`).
- Normalized diff artifacts with `score=None` to an empty score map in the CLI model
  layer; PR-comment dependency-overview rendering no longer crashes on missing or
  partial score data.
- Defaulted missing badge values to a valid `100%` fallback rather than producing
  invalid badge URLs.

## 2.2.85

- Added four hidden `--reach-continue-on-*` flags in preparation for Coana CLI v15:
  `--reach-continue-on-analysis-errors`, `--reach-continue-on-install-errors`,
  `--reach-continue-on-missing-lock-files`, `--reach-continue-on-no-source-files`.
  Each forwards to the matching Coana flag and opts out of one of Coana v15's new
  halt-by-default behaviors. No-op against today's default Coana version; will take
  effect automatically once Coana v15 becomes the default.

## 2.2.83

- Fixed branch detection in detached-HEAD CI checkouts. When `git name-rev --name-only HEAD` returned an output with a suffix operator (e.g. `remotes/origin/master~1`, `master^0`), the `~N`/`^N` was previously passed through as the branch name and rejected by the Socket API as an invalid Git ref. The suffix is now stripped before the prefix split, producing the bare branch name.

## 2.2.81

- Fixed GitLab security report schema compliance: corrected schema validation errors so
  Socket-produced reports parse cleanly under GitLab's dependency-scanning ingestion.
- Populated scan alert data in the GitLab security report so previously-empty alert
  sections now carry the expected findings.

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
