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
