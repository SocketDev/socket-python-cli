# Troubleshooting

## API token permissions

The CLI authenticates with a single Socket organization API token. A token missing a
permission usually does **not** fail the run. Several paths fall back or skip work and
leave only a warning in the log.

### Scopes to grant

For a least-privilege CI token, grant these:

| Scope | Needed for |
|:---|:---|
| `repo:list` | Looking up the repository and its head scan, on every run |
| `repo:create` | Creating the repository on its first scan. Without it, a scan of a repository Socket has not seen yet exits `2`; see [below](#a-missing-repository-permission-can-exit-2) |
| `full-scans:create` | Creating the scan, on every run. `--reach` also uploads manifests and finalizes the reachability scan under this scope |
| `full-scans:list` | Every comparison, the `--base-commit-sha` lookup, and fetching scan contents for `--enable-json`, `--enable-sarif`, `--enable-gitlab-security` and `--generate-license` on a full scan |
| `diff-scans:create` | Creating the comparison on a diff-producing run |
| `diff-scans:list` | Polling for the comparison, and finding an existing one |
| `packages:list` | `--generate-license` only |

The scopes each endpoint checks are listed in the
[API reference](https://docs.socket.dev/reference). A few calls check no scope and work
with any valid token for the organization: `GET organizations`, `GET report/supported`,
and the telemetry event posted when someone replies to a Socket comment with an ignore
command.

### The CI/CD setup guide's list is incomplete for this CLI

The [CI/CD token setup guide](https://docs.socket.dev/docs/create-socket-api-key-for-cicd)
lists nine scopes:

`repo:list`, `repo:create`, `repo:update`, `security-policy:read`,
`triage:alerts-list`, `triage:alerts-update`, `full-scans:list`, `full-scans:create`,
`packages:list`

**It does not include `diff-scans:create` or `diff-scans:list`**, and every
diff-producing run needs both. A token set up exactly as that guide describes always
falls back to the older comparison path; see
[the next section](#apiaccessdenied-on-the-scan-comparison). Add the two scopes.

The guide's list also includes four scopes this CLI never uses: `repo:update`,
`security-policy:read`, `triage:alerts-list` and `triage:alerts-update`. Other Socket
tooling uses them, so leave them on a shared token. A token used only by `socketcli`
can drop them.

### API calls by run type

Every run:

| API call | Scope | Purpose |
|:---|:---|:---|
| `GET organizations` | none | Resolve the org ID and slug from the token |
| `GET report/supported` | none | Fetch supported manifest patterns. On failure the CLI uses a bundled list that covers fewer ecosystems |
| `GET orgs/{org}/repos/{repo}` | `repo:list` | Look up the repository and its head scan |
| `POST orgs/{org}/repos` | `repo:create` | Create the repository, **only attempted if the lookup above fails** |
| `POST orgs/{org}/full-scans` | `full-scans:create` | Create the new scan, and the temporary empty baseline on a first scan |

Diff-producing runs (see [which runs compare](#apiaccessdenied-on-the-scan-comparison)) add:

| API call | Scope | Purpose |
|:---|:---|:---|
| `POST orgs/{org}/diff-scans/from-ids` | `diff-scans:create` and `full-scans:list` | Create the comparison (preferred path) |
| `GET orgs/{org}/diff-scans` | `diff-scans:list` | Find the existing comparison when creation returns 409 |
| `GET orgs/{org}/diff-scans/{id}` | `diff-scans:list` | Poll for the computed comparison |
| `GET orgs/{org}/full-scans/diff` | `full-scans:list` | Streaming comparison (fallback path) |

Flags add:

| Flag | API calls | Scope |
|:---|:---|:---|
| `--reach` | `GET organizations` (plan check), `POST orgs/{org}/upload-manifest-files`, `POST tier1-reachability-scan/finalize` | none, `full-scans:create`, `full-scans:create` |
| `--base-commit-sha` | `GET orgs/{org}/full-scans` (find the scan for that commit or a scanned ancestor) | `full-scans:list` |
| `--generate-license` | `POST orgs/{org}/purl` | `packages:list` |
| `--enable-json`, `--enable-sarif`, `--enable-gitlab-security` or `--generate-license` on a full scan | `GET orgs/{org}/full-scans/{id}` (scan contents) | `full-scans:list` |

`--reach` also runs the Coana CLI with the same token, and its reachability calls
check `full-scans:create`.

## `APIAccessDenied` on the scan comparison

Any run that produces a diff first tries the diff-scans endpoints. A token without the
`diff-scans:*` scopes logs a warning and continues on the older path:

```
Diff scan comparison failed with APIAccessDenied(Insufficient permissions), falling back to the streaming scan comparison
```

The scan still succeeds and the diff results are the same, so this is easy to miss.

**Which runs produce a diff:**

| Run | Compares? |
|:---|:---|
| PR/MR event with `--scm github` / `--scm gitlab` | Yes |
| Any other event with `--scm github` / `--scm gitlab` (branch and default-branch pushes) | No — creates a full scan |
| No SCM integration (`--scm api`, the default), including `--enable-diff` and `--ignore-commit-files` | Yes |
| No supported manifest in the changed-file set | No — falls back to a full scan |

Before 2.9.0 an SCM-integrated branch push also compared, so a pipeline scanning only
pushes (`--pr-number 0 --default-branch`) hit this too. If you are diagnosing an older
run, that is why the warning can appear in a log with no pull request in sight.

**Which scope is missing.** The fallback calls `GET orgs/{org}/full-scans/diff`, which
checks `full-scans:list`. If the fallback produces results, the token already has
`full-scans:list`, so the missing grant is `diff-scans:create`, `diff-scans:list`, or
both. If the fallback also fails, `full-scans:list` is missing too.

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

This usually happens on the first scan of a repository Socket has not seen, when the
token lacks `repo:create`. A token without `repo:list` can end up here even for
a repository that exists, because its lookup fails and the CLI then tries to create it. The log shows `API failure while creating repository`, and on a
403 adds:

```
A 403 here usually means the API token is missing the repo:create scope.
```

Grant `repo:create`, or create the repository in Socket before the first pipeline run.

## Baseline scans that do not appear in the dashboard

On the first scan of a repository or branch there is no head scan to diff against, so
the CLI creates a **temporary empty baseline** and compares to that:

```
No previous scan found - creating empty baseline scan
Baseline selected: source=empty scan_id="<baseline>"
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

## Reachability on a restricted network

- `Failed to run reachability analysis: HTTPSConnectionPool(host='storage.googleapis.com', ...)`: the engine download is blocked. Allow `storage.googleapis.com`, or set `HTTPS_PROXY`. An npm mirror does not cover it.
- Every vulnerability reported as `INSTALL ERROR`: the engine could not install your dependencies. Allow the ecosystem's package registry, or install dependencies in the target path before running `--reach`.
- See **Reachability network access** in the [CLI reference](cli-reference.md) for the full list of hosts.

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
