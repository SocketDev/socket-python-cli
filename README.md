# Socket Security CLI

Socket Python CLI for Socket scans, diff reporting, reachability analysis, and SARIF/GitLab exports.

Comprehensive docs are available in [`docs/`](https://github.com/SocketDev/socket-python-cli/tree/main/docs) for full flag reference, CI/CD-specific guidance, and contributor setup.

## Quick start

### 1) Install

```bash
pip install socketsecurity
```

### 2) Authenticate

```bash
export SOCKET_SECURITY_API_TOKEN="<token>"
```

### 3) Run a basic scan

```bash
socketcli --target-path .
```

## Common use cases

This section covers the paved path/common workflows.
For advanced options and exhaustive details, see [`docs/cli-reference.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/cli-reference.md).
For CI/CD-specific guidance, see [`docs/ci-cd.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/ci-cd.md).

### Basic policy scan (no SARIF)

```bash
socketcli --target-path .
```

### GitLab dependency-scanning report

```bash
socketcli --enable-gitlab-security --gitlab-security-file gl-dependency-scanning-report.json
```

### PR scan diffed against the merge base

By default, PR scans are diffed against the repository's latest head scan. To diff against
the exact commit your PR branched from instead, pass the merge base as the baseline:

```bash
BASE_SHA=$(git merge-base origin/main HEAD)
socketcli --pr-number 123 --base-commit-sha "$BASE_SHA"
```

> **Requirement:** `--base-commit-sha` only works if Socket already has a full scan for that
> exact commit. In practice this means your CI must run `socketcli` on **every commit that
> lands on your default branch** — not just some of them. If merges can land without a scan
> (skipped/canceled builds, `[skip ci]`, path-filtered pipelines), the PR scan will fail with
> exit code 3 rather than silently diff against the wrong baseline. See
> [`docs/cli-reference.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/cli-reference.md)
> for the full requirements and a backfill pattern that makes PR jobs self-sufficient.

A specific full scan ID also works: `--base-scan-id <id>`.

## SARIF use cases

### Full-scope reachable SARIF (grouped alerts)

```bash
socketcli \
  --reach \
  --sarif-file results.sarif \
  --sarif-scope full \
  --sarif-grouping alert \
  --sarif-reachability reachable \
  --disable-blocking
```

### Diff-scope reachable SARIF (PR/CI gating)

```bash
socketcli \
  --reach \
  --sarif-file results.sarif \
  --sarif-scope diff \
  --sarif-reachability reachable \
  --strict-blocking
```

### Full-scope SARIF (instance-level detail)

```bash
socketcli \
  --reach \
  --sarif-file results.sarif \
  --sarif-scope full \
  --sarif-grouping instance \
  --sarif-reachability all \
  --disable-blocking
```

## Choose your mode

| Use case | Recommended mode | Key flags |
|:--|:--|:--|
| Basic policy enforcement in CI | Diff-based policy check | `--strict-blocking` |
| Legal/compliance artifact generation | Legal preset | `--legal` |
| Reachable-focused SARIF for reporting | Full-scope grouped SARIF | `--reach --sarif-scope full --sarif-grouping alert --sarif-reachability reachable --sarif-file <path>` |
| Detailed reachability export for investigations | Full-scope instance SARIF | `--reach --sarif-scope full --sarif-grouping instance --sarif-reachability all --sarif-file <path>` |
| Net-new PR findings only | Diff-scope SARIF | `--reach --sarif-scope diff --sarif-reachability reachable --sarif-file <path>` |

Dashboard parity note:
- Full-scope SARIF is the closest match for dashboard-style filtering.
- Exact result counts can still differ from the dashboard due to backend/API consolidation differences and grouping semantics.
- See [`docs/troubleshooting.md#dashboard-vs-cli-result-counts`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/troubleshooting.md#dashboard-vs-cli-result-counts).

## Config files (`--config`)

Use `--config <path>` with `.toml` or `.json` to avoid long command lines.

Precedence order:

`CLI flags` > `environment variables` > `config file` > `built-in defaults`

Example:

```toml
[socketcli]
repo = "example-repo"
reach = true
sarif_scope = "full"
sarif_grouping = "alert"
sarif_reachability = "reachable"
sarif_file = "reachable.sarif"
```

Equivalent JSON:

```json
{
  "socketcli": {
    "repo": "example-repo",
    "reach": true,
    "sarif_scope": "full",
    "sarif_grouping": "alert",
    "sarif_reachability": "reachable",
    "sarif_file": "reachable.sarif"
  }
}
```

Run:

```bash
socketcli --config .socketcli.toml --target-path .
```

Legal/compliance preset example:

```bash
socketcli --legal --target-path .
```

This preset enables license generation and writes default artifacts unless you override them:
- `socket-report.json`
- `socket-summary.txt`
- `socket-report-link.txt`
- `socket-sbom.json`
- `socket-license.json`

FOSSA-compatibility shaped legal artifacts:

```bash
socketcli --legal-format fossa --target-path .
```

This switches the JSON report and legal artifact payloads to FOSSA-style compatibility shapes:
- the analyze artifact becomes a `project` / `vulnerability` / `licensing` / `quality` report
- the SBOM artifact becomes a FOSSA-attribution-style payload with `copyrightsByLicense`, `deepDependencies`, `directDependencies`, `licenses`, and `project` keys

When `--legal-format fossa` is used without explicit output paths, the defaults are closer to the FOSSA pipeline contract:
- `fossa-analyze.json`
- `fossa-test.txt`
- `fossa-link.txt`
- `fossa-sbom.json`

Reference sample configs:

TOML:
- [`examples/config/sarif-dashboard-parity.toml`](https://github.com/SocketDev/socket-python-cli/blob/main/examples/config/sarif-dashboard-parity.toml)
- [`examples/config/sarif-instance-detail.toml`](https://github.com/SocketDev/socket-python-cli/blob/main/examples/config/sarif-instance-detail.toml)
- [`examples/config/sarif-diff-ci-cd.toml`](https://github.com/SocketDev/socket-python-cli/blob/main/examples/config/sarif-diff-ci-cd.toml)

JSON:
- [`examples/config/sarif-dashboard-parity.json`](https://github.com/SocketDev/socket-python-cli/blob/main/examples/config/sarif-dashboard-parity.json)
- [`examples/config/sarif-instance-detail.json`](https://github.com/SocketDev/socket-python-cli/blob/main/examples/config/sarif-instance-detail.json)
- [`examples/config/sarif-diff-ci-cd.json`](https://github.com/SocketDev/socket-python-cli/blob/main/examples/config/sarif-diff-ci-cd.json)

## CI/CD examples

Prebuilt workflow examples:

- [GitHub Actions](https://github.com/SocketDev/socket-python-cli/blob/main/workflows/github-actions.yml)
- [Buildkite](https://github.com/SocketDev/socket-python-cli/blob/main/workflows/buildkite.yml)
- [GitLab CI](https://github.com/SocketDev/socket-python-cli/blob/main/workflows/gitlab-ci.yml)
- [Bitbucket Pipelines](https://github.com/SocketDev/socket-python-cli/blob/main/workflows/bitbucket-pipelines.yml)

Minimal pattern:

```yaml
- name: Run Socket CLI
  run: socketcli --config .socketcli.toml --target-path .
  env:
    SOCKET_SECURITY_API_TOKEN: ${{ secrets.SOCKET_SECURITY_API_TOKEN }}
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean scan — no blocking issues (or `--disable-blocking` set) |
| `1`  | Blocking security finding(s) detected |
| `2`  | Scan interrupted (SIGINT / Ctrl+C) |
| `3`  | Infrastructure or API error (timeout, network failure, unexpected error) |

`--exit-code-on-api-error <N>` remaps the infrastructure-error code (`3`) to any
value — e.g. a Buildkite
[`soft_fail`](https://buildkite.com/docs/pipelines/configure/step-types/command-step)
code, or `0` to swallow infra errors. Exit `3` is a Socket convention, not an
industry standard.

### How these options interact

The two flags that affect exit codes can cancel each other out, so the order of
precedence matters:

- **`--disable-blocking` wins over everything.** It forces exit `0` for *all*
  outcomes — security findings *and* infrastructure errors. If you set it,
  `--exit-code-on-api-error` has no effect (you'll always get `0`).
- **`--exit-code-on-api-error` only applies when `--disable-blocking` is *not*
  set.** It changes the infra-error code (and the generic-error code); it never
  touches the security-finding code (`1`).

So for the common "don't let Socket outages block my pipeline, but still fail on
real findings" goal, use `--exit-code-on-api-error` **without** `--disable-blocking`:

```yaml
# Buildkite: soft-fail only on infrastructure errors, still block on findings
steps:
  - label: ":lock: Socket Security Scan"
    command: "socketcli --exit-code-on-api-error 100 ..."   # NOT --disable-blocking
    soft_fail:
      - exit_status: 100
```

Combining `--disable-blocking` with `--exit-code-on-api-error 100` would make the
scan exit `0` on *both* findings and outages — the `soft_fail: 100` rule would
never match, and real findings would stop blocking. That's usually not what you
want.

## Common gotchas

See [`docs/troubleshooting.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/troubleshooting.md#common-gotchas).

## Quick verification checks

After generating SARIF files, validate shape/count quickly:

```bash
jq '.runs[0].results | length' results.sarif
jq -r '.runs[0].results[]?.properties.reachability' results.sarif | sort -u
```

For side-by-side comparisons:

```bash
jq '.runs[0].results | length' sarif-dashboard-parity-reachable.sarif
jq '.runs[0].results | length' sarif-full-instance-all.sarif
jq '.runs[0].results | length' sarif-diff-reachable.sarif
```

## Documentation reference

- Full CLI reference: [`docs/cli-reference.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/cli-reference.md)
- CI/CD guide: [`docs/ci-cd.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/ci-cd.md)
- Troubleshooting guide: [`docs/troubleshooting.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/troubleshooting.md)
- Development guide: [`docs/development.md`](https://github.com/SocketDev/socket-python-cli/blob/main/docs/development.md)
