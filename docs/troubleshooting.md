# Troubleshooting

## API token permissions

The CLI authenticates with a single Socket organization API token. Every run needs
more than "create a scan" access, and a token that is missing a permission usually
does **not** fail loudly — several paths degrade or fall back with only a warning.

### What every run calls

These are exercised on any invocation, regardless of flags:

| API call | Purpose |
|:---|:---|
| `GET organizations` | Resolve the org ID and slug from the token |
| `GET report/supported` | Fetch supported manifest patterns (falls back to a bundled list on failure) |
| `GET orgs/{org}/repos/{repo}` | Look up the repository |
| `POST orgs/{org}/repos` | Create the repository — **only attempted if the lookup above fails** |
| `POST orgs/{org}/full-scans` | Create the new scan |

### What diff-producing runs add

| API call | Purpose |
|:---|:---|
| `POST orgs/{org}/diff-scans/from-ids` | Create the comparison (preferred path) |
| `GET orgs/{org}/diff-scans` | Resolve an existing comparison on a 409 |
| `GET orgs/{org}/diff-scans/{id}?cached=true` | Poll for the computed comparison |
| `GET orgs/{org}/full-scans/diff` | Legacy streaming comparison (fallback path) |
| `GET orgs/{org}/full-scans/{id}` | Resolve a baseline for `--base-scan-id` / `--base-commit-sha` |

The diff-scans path is the one with published scope names: `diff-scans:create`,
`diff-scans:list` and `full-scans:list`. For the rest of the calls above, grant the
token access to the corresponding resource; if you need the exact scope identifiers to
provision a least-privilege token, ask Socket support rather than inferring them from
the endpoint paths.

### What individual flags add

| Flag | Additional API calls |
|:---|:---|
| `--reach` | Manifest upload, `GET organizations` (plan check), full-scan tier-1 finalize |
| `--generate-license` | `POST purl` |
| `--enable-json` / `--enable-sarif` / `--enable-gitlab-security` on a full scan | `GET orgs/{org}/full-scans/{id}` (metadata), full-scan stream, and `POST license-metadata` for every package that carries a license |
| `--sbom-file` | `GET orgs/{org}/export/cdx/{id}` |

## `APIAccessDenied` on the scan comparison

Any run that produces a diff — PR/MR events, **plain pushes on the default branch**,
and `--enable-diff` / `--ignore-commit-files` runs without an SCM integration — first
tries the diff-scans endpoints. A token without the `diff-scans:*` permissions logs a
warning and silently continues on the older path:

```
Diff scan comparison failed with APIAccessDenied(Insufficient permissions), falling back to the streaming scan comparison
```

The scan still succeeds and the diff results are the same, so this is easy to miss.

Note that this is *not* limited to PR/MR runs. A pipeline that only ever scans pushes
(`--pr-number 0 --default-branch`) still hits it.

**Which permission is missing.** The fallback path is `GET orgs/{org}/full-scans/diff`,
a full-scans read. If you see the fallback produce results, your token already has
full-scans read, and the missing grants are the two `diff-scans:*` permissions — not
`full-scans:list`. If the fallback *also* fails, the gap is broader.

**Why the diff-scans path is preferred.** It polls with short, bounded requests rather
than holding one connection open while the backend computes, which is what lets large
comparisons survive network idle timeouts — notably Azure NAT gateways, which reap idle
connections after four minutes and surface as an intermittent `ConnectionResetError`.
Falling back costs resilience, not correctness.

The two paths can take noticeably different amounts of time on the same repository,
because cached diff-scan responses always embed per-package license details while the
streaming comparison requests a lean payload. On a large dependency tree, compare the
`Diff scan comparison ready in ...` timing against the `Diff Report Gathered in ...`
total before assuming either path is at fault.

## A missing repository permission can exit 2

If the repository lookup fails, the CLI assumes the repo does not exist yet and tries
to create it. When the token cannot do either, the run exits with code **2** — which
[the exit code table](../README.md#exit-codes) otherwise documents as a keyboard
interrupt. That exit also bypasses `--disable-blocking` and `--exit-code-on-api-error`,
so it fails the pipeline even when you have asked for infrastructure errors to be
non-blocking.

If a job dies with exit 2 and `Failed to create repository` or `API failure while
creating repository` in the log, check the token's repository permissions before
looking anywhere else.

## Baseline scans that do not appear in the dashboard

On the first scan of a repository or branch there is no head scan to diff against, so
the CLI creates a **temporary empty baseline** and compares to that:

```
No previous scan found - creating empty baseline scan
Comparing scans - Head scan ID: <baseline>, New scan ID: <real scan>
```

The baseline is created as a temporary scan and is deliberately not set as the
repository head or default branch, so it does not show up as a repository scan in the
dashboard. Looking it up by ID will come up empty. This is expected — the scan to look
at is the "New scan ID".

Because everything is new relative to an empty baseline, the first run also reports
every package as added and zero as unchanged.

## Reachability scan IDs are not full-scan IDs

With `--reach`, the CLI logs an extra identifier before the normal scan flow starts:

```
Reachability scan ID: <tier-1 reachability scan ID>
```

That value is `tier1ReachabilityScanId`, read out of `.socket.facts.json`. It
identifies the reachability analysis run, not a Socket full scan, and will not resolve
in the dashboard's scan views. The full scan to look at is the "New scan ID" reported
by the comparison step that follows.

## Common gotchas

- In diff scope, `--strict-blocking` uses a stricter alert set (`new + unchanged`) for blocking checks and diff-based output selection.
- `--sarif-scope full` requires `--reach`.
- In `--sarif-scope full` with `--sarif-file`, SARIF JSON is written to file and stdout JSON is suppressed.
- `--sarif-grouping alert` currently applies to `--sarif-scope full`.

## Dashboard vs CLI result counts

Differences in result counts can be valid, even when filtering appears similar.

Common reasons:

- `diff` vs `full` data source:
  - `--sarif-scope diff` is based on diff alerts (typically net-new in the compared scan context).
  - `--sarif-scope full` is based on full reachability facts data.
- Consolidation differences:
  - Dashboard and API/CLI can apply different consolidation/grouping rules.
  - `--sarif-grouping alert` and `--sarif-grouping instance` intentionally produce different row counts.
- Policy vs dataset:
  - `--strict-blocking` only affects diff-scope behavior and does not make diff output equivalent to full dashboard data.
- Reachability data availability:
  - If reachability analysis partially fails and falls back to precomputed reachability, counts can shift.

Recommended comparison path:

1. Use full-scope SARIF for parity-oriented comparisons.
2. Keep grouping fixed (`alert` for dashboard-style rollups, `instance` for detailed exports).
3. Compare reachability filters with the same mode and grouping across runs.

## Save submitted file list

Use `--save-submitted-files-list` to inspect exactly what was sent for scanning.

```bash
socketcli --save-submitted-files-list submitted_files.json
```

Output includes:

- timestamp
- total file count
- total size
- complete submitted file list

## Save manifest archive

Use `--save-manifest-tar` to export discovered manifest files as `.tar.gz`.

```bash
socketcli --save-manifest-tar manifest_files.tar.gz
```

Combined example:

```bash
socketcli --save-submitted-files-list files.json --save-manifest-tar backup.tar.gz
```

## Octopus merge note

For octopus merges (3+ parents), Git can report incomplete changed-file sets because default diff compares against the first parent.

If needed, force full scan behavior with:

- `--ignore-commit-files`

## GitLab report troubleshooting

If report is not visible in GitLab Security Dashboard:

- verify `dependency_scanning` artifact is configured in `.gitlab-ci.yml`
- verify job completed and artifact uploaded
- verify report file schema is valid

If vulnerabilities array is empty:

- this can be expected when no actionable security issues are present in the result scope
- confirm expected scope/flags and compare with Socket dashboard data
