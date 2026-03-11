# Troubleshooting

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
  - If reachability analysis partially fails and falls back to precomputed tiers, counts can shift.

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
