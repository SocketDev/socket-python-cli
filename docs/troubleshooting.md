# Troubleshooting

## Unexpected CI exit status

| Symptom | What to check |
|---------|---------------|
| Exit `2`, even with `--disable-blocking` | Fix the flags or configuration reported in the logs. Check config-file readability, native boolean/integer values, a positive timeout and the `files` array. Usage errors are never suppressed. |
| Exit `3` with no reported findings | Check tokens, scopes, baseline lookup and scan-completeness errors. This is a failed evaluation; `--exit-code-on-api-error` can remap its code. |
| Ctrl+C is treated as a configuration error | Update wrapper/CI rules: Ctrl+C changed from `2` to `130` in 2.13.0. |
| Exit `0` despite expected blockers | Check `--disable-blocking`, remapping to `0`, and whether the run produced a full scan instead of a diff. Full scans do not gate on findings. |

See [Exit codes in CI](ci-cd.md#exit-codes-in-ci) for the flag combinations and
[upgrade notes](../README.md#upgrading-from-212-or-earlier) for older pipeline rules.

## Repository lookup or creation fails

A run that compares scans looks up the repository first, unless `--base-scan-id` or
`--base-commit-sha` is set. A token missing a repository scope stops there with the
infrastructure-error code (`3` by default):

| Log message | Missing scope |
|-------------|---------------|
| `Failed to get repository <repo> (HTTP 403). The API token may be missing the repo:list scope.` | `repo:list` |
| `API failure while creating repository <repo> (HTTP 403): ...`, then `A 403 here usually means the API token is missing the repo:create scope.` | `repo:create`. Only needed when the repository does not exist yet |

Both failures follow `--disable-blocking` and `--exit-code-on-api-error`. Before
2.13.0, any failed lookup was treated as a missing repository, so a token without
`repo:list` ended in the `repo:create` message, and the run exited `2` whatever
either flag said.

## API token permissions

The CLI authenticates with a single Socket organization API token. Most missing scopes
fail the run with an API error. The two `diff-scans` scopes are the exception: without
them the run falls back to an older comparison and only logs a warning.

### Scopes to grant

For a least-privilege CI token, grant these:

| Scope | Needed for | Without it |
|:---|:---|:---|
| `full-scans:create` | Creating the scan, on every run. `--reach` also locates the analysis engine, uploads manifests and records the reachability scan under it | The run fails |
| `full-scans:list` | Finding the baseline scan and comparing against it, on every run that compares scans. Also fetching scan contents for `--enable-json`, `--enable-sarif`, `--enable-gitlab-security` and `--generate-license` on a full scan | Those runs fail |
| `diff-scans:create` | Creating the comparison | The run [falls back](#apiaccessdenied-on-the-scan-comparison) with a warning |
| `diff-scans:list` | Polling for the comparison, and finding an existing one | The same fallback |
| `repo:list` | Looking up the repository's default branch, on runs that compare scans without `--base-scan-id` or `--base-commit-sha` | Those runs fail; see [Repository lookup or creation fails](#repository-lookup-or-creation-fails) |
| `repo:create` | Creating the repository when that lookup finds none | The first comparison for a repository Socket has not seen fails |
| `packages:list` | `--generate-license` only | Those runs fail |

A failed run exits with the API-error code: `3` by default, the value of
`--exit-code-on-api-error` when set, or `0` with `--disable-blocking`.

Scopes are grouped by their prefix, and granting a group grants every scope in it:
`full-scans` covers `full-scans:create`, `full-scans:list` and `full-scans:delete`. The
dashboard's token dialog lists each scope under its group. A token with the groups
`full-scans`, `diff-scans`, `repo` and `packages` therefore works too; it just holds
more than this CLI uses.

The scopes each endpoint checks are listed in the
[API reference](https://docs.socket.dev/reference). `GET organizations` and the
telemetry event posted when someone replies to a Socket comment with an ignore command
check no scope, so any valid token for the organization works. `GET report/supported`
needs no token at all.

**Tokens restricted to specific repositories** can scan those repositories but cannot
set up a new one. The API rejects them on `POST orgs/{org}/repos`, and
`POST orgs/{org}/full-scans` does not create a missing repository for them, whatever
scopes they hold. They are also rejected on `POST orgs/{org}/purl`, so
`--generate-license` needs a token with organization-wide repository access.

### Tokens with the nine-scope CI/CD list

The [CI/CD token setup guide](https://docs.socket.dev/docs/create-socket-api-key-for-cicd)
was written before the diff-scans endpoints existed. Tokens created from its
nine-scope list hold exactly these:

`repo:list`, `repo:create`, `repo:update`, `security-policy:read`,
`triage:alerts-list`, `triage:alerts-update`, `full-scans:list`, `full-scans:create`,
`packages:list`

**That list has neither `diff-scans:create` nor `diff-scans:list`**, and every run
that compares scans uses both. A token with only those nine scopes always falls back
to the older comparison path; see
[the next section](#apiaccessdenied-on-the-scan-comparison). Add the two scopes.

The list also has four scopes this CLI never uses: `repo:update`,
`security-policy:read`, `triage:alerts-list` and `triage:alerts-update`. A token used
only by `socketcli` can drop them.

### API calls by run type

Every run:

| API call | Scope | Purpose |
|:---|:---|:---|
| `GET organizations` | none | Resolve the org ID and slug from the token |
| `POST python-cli-runs` | `full-scans:create` | Register the run. When log upload is on (`--upload-logs`, or enabled for the organization), `POST python-cli-runs/{id}/logs` and `POST python-cli-runs/{id}/finalize` follow under the same scope. A failure in any of the three is ignored |
| `GET report/supported` | none | Fetch supported manifest patterns |
| `POST orgs/{org}/full-scans` | `full-scans:create` | Create the new scan. With an organization-wide token, the server creates the repository if it does not exist yet |

Comment events with `--scm github` or `--scm gitlab` create no scan.

Runs that compare scans (see [which runs compare](#apiaccessdenied-on-the-scan-comparison)) add:

| API call | Scope | Purpose |
|:---|:---|:---|
| `GET orgs/{org}/repos/{repo}` | `repo:list` | Look up the repository's default branch. Skipped with `--base-scan-id` or `--base-commit-sha` |
| `POST orgs/{org}/repos` | `repo:create` | Create the repository, **only attempted when the lookup above finds none** |
| `GET orgs/{org}/full-scans` | `full-scans:list` | Find the baseline: the newest matching scan on the default branch, or with `--base-commit-sha` the scan for that commit or a scanned ancestor. Skipped with `--base-scan-id` |
| `POST orgs/{org}/full-scans` | `full-scans:create` | Create a temporary empty baseline when no scan matches |
| `POST orgs/{org}/diff-scans/from-ids` | `diff-scans:create` and `full-scans:list` | Create the comparison (preferred path) |
| `GET orgs/{org}/diff-scans` | `diff-scans:list` | Find the existing comparison when creation returns 409 |
| `GET orgs/{org}/diff-scans/{id}` | `diff-scans:list` | Poll for the computed comparison |
| `GET orgs/{org}/full-scans/diff` | `full-scans:list` | Streaming comparison (fallback path). The API marks this endpoint as deprecated |

Flags add:

| Flag | API call | Scope |
|:---|:---|:---|
| `--reach` | `GET organizations` (plan check) | none |
| `--reach` | `POST orgs/{org}/coana-cli/artifacts` (locate the analysis engine download, only when it is not cached) | `full-scans:create` or `fixes:list` |
| `--reach` | `POST orgs/{org}/upload-manifest-files`, `POST tier1-reachability-scan/finalize` | `full-scans:create` |
| `--generate-license` | `POST orgs/{org}/purl` | `packages:list` |
| `--enable-json`, `--enable-sarif`, `--enable-gitlab-security` or `--generate-license` on a full scan | `GET orgs/{org}/full-scans/{id}` (scan contents) | `full-scans:list` |
| `--strict-blocking`, `--enable-gitlab-security` or `--legal-format fossa` on a run that compares scans | `GET orgs/{org}/full-scans/{id}` (existing alerts) | `full-scans:list` |

`--reach` also runs the analysis engine with the same token. The engine reports to the
`tier1-reachability-scan/*` endpoints, which check `full-scans:create`.

## `APIAccessDenied` on the scan comparison

Any run that compares scans first tries the diff-scans endpoints. A token without the
`diff-scans:create` and `diff-scans:list` scopes logs a warning and continues on the
older path:

```
Diff scan comparison failed with APIAccessDenied(Insufficient permissions), falling back to the streaming scan comparison
```

The scan still succeeds and the diff results are the same, so this is easy to miss.

**Which runs compare scans:**

| Run | Compares? |
|:---|:---|
| Pull request or merge request run with `--scm github` / `--scm gitlab` | Yes |
| Comment event with `--scm github` / `--scm gitlab` | No. It creates no scan |
| Any other event with `--scm github` / `--scm gitlab` (branch and default-branch pushes) | No. It creates a full scan |
| No SCM integration (`--scm api`, the default) | Yes |

In the rows that compare, the CLI first looks for a supported manifest among the
commit's changed files, or among `--files` when that is given. If it finds none, or
the directory is not a git repository and `--files` is not given, it creates a full
scan instead. `--ignore-commit-files` in a git repository and `--enable-diff` outside
one skip that check, so those runs always compare.

Before 2.9.0 an SCM-integrated branch push also compared, so a pipeline scanning only
pushes (`--pr-number 0 --default-branch`) hit this too. If you are diagnosing an older
run, that is why the warning can appear in a log with no pull request in sight.

**Which scope is missing.** The fallback calls `GET orgs/{org}/full-scans/diff`, which
checks `full-scans:list`. When the fallback succeeds, the missing scope is
`diff-scans:create`, `diff-scans:list`, or both. A token without `full-scans:list`
does not get that far: the CLI lists full scans to pick the baseline before it compares
anything, so the run fails first with `Failed to resolve the matching head scan for
repo ...` and the API-error exit code. With `--base-scan-id` that lookup is skipped,
and the run fails at the fallback instead. A fallback that fails another way, such as a
timeout or a dropped connection, says nothing about scopes.

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

## Baseline scans that do not appear in the dashboard

A run that compares scans picks its baseline from the repository's default branch: the
newest scan there with the same scan type (`socket`, or `socket_tier1` with `--reach`)
and, with `--workspace`, the same workspace. `--base-scan-id` and `--base-commit-sha`
override that choice. When no scan matches, the CLI creates a **temporary empty
baseline** and compares to that:

```
No previous scan found - creating empty baseline scan
Baseline selected: source=empty scan_id="<baseline>"
Comparing scans - Head scan ID: <baseline>, New scan ID: <real scan>
```

The baseline is created as a temporary scan and is deliberately not set as the
repository head or default branch, so it does not show up as a repository scan in the
dashboard. Looking it up by ID will come up empty. This is expected — the scan to look
at is the "New scan ID".

Because everything is new relative to an empty baseline, that comparison reports
every package as added and zero as unchanged. This happens on a repository's first
comparison, and also the first time it is compared under a different scan type or
workspace, such as the first `--reach` run on a repository that only has regular
scans. A new branch compares against the default branch's newest matching scan, not an
empty baseline.

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

## Packages installed outside the lockfile

Packages present only on disk, such as packages that a `postinstall` script adds without updating the lockfile, can be missing from a manifest-based scan.

`--include-module-folders` lets the CLI discover supported manifests in `node_modules`, `bower_components`, and `jspm_packages`, including nested directories. Other directory and path exclusions still apply, and discovery skips symlinked directories. Socket resolves the dependencies the manifests declare, including `devDependencies`. This can add findings for dependencies absent from your installed tree. With `--reach`, the CLI also includes these files in the manifest upload for reachability analysis.

For npm projects, generate a CycloneDX software bill of materials (SBOM) from the installed tree. The example uses Node.js 20.18 or newer and npm 9 or newer. Run it from the scan root with a Socket API token configured.

```bash
npm ci &&
  npx --yes @cyclonedx/cyclonedx-npm@7.0.1 --omit dev --output-format JSON --output-file installed.cdx.json &&
  socketcli --target-path .
```

The example excludes development dependencies. To include them, remove `--omit dev` and run the install and generator without production-only npm settings or `NODE_ENV=production`. If npm reports a dependency-tree error, inspect it first. Use the generator's `--ignore-npm-errors` option only if the tree npm returns contains the packages you intend to scan.

The CLI discovers CycloneDX files such as `bom.json`, `*.cdx.json`, and `*.cyclonedx.json` (or their `.xml` equivalents) alongside the lockfile. Leave `--include-module-folders` off when you only want to add the SBOM.

- For PR comparisons, generate the SBOM with the same settings before the default-branch and PR scans. Add `--ignore-commit-files` to the PR scan so it runs a comparison even on commits that change no tracked manifest. A generated SBOM outside the Git diff does not trigger comparison mode on its own.
- The SBOM covers packages present when it is generated. Packages fetched later or installed outside the tree, such as tools fetched into the npm cache by `npx`, are outside its scope.

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
