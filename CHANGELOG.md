# Changelog

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
