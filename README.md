# Socket Security CLI

Socket Python CLI for Socket scans, diff reporting, reachability analysis, and SARIF/GitLab exports.

Comprehensive docs are available in [`docs/`](docs/) for full flag reference, CI/CD-specific guidance, and contributor setup.

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
For advanced options and exhaustive details, see [`docs/cli-reference.md`](docs/cli-reference.md).
For CI/CD-specific guidance, see [`docs/ci-cd.md`](docs/ci-cd.md).

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

## Scope and behavior matrix

| Goal | Key flags | Notes |
|:--|:--|:--|
| Match dashboard-style reachable view | `--sarif-scope full --sarif-grouping alert --sarif-reachability reachable` | Best parity path for customer evaluations |
| Capture all reachability findings | `--sarif-scope full --sarif-grouping instance --sarif-reachability all` | Most verbose output |
| Gate only on new findings | `--sarif-scope diff` | Diff mode can validly return empty SARIF |
| Filter to reachable only (legacy syntax) | `--sarif-reachable-only` | Backward-compatible alias for `--sarif-reachability reachable` |

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

Run:

```bash
socketcli --config .socketcli.toml --target-path .
```

Reference sample configs:

- [`examples/config/sarif-dashboard-parity.toml`](examples/config/sarif-dashboard-parity.toml)
- [`examples/config/sarif-instance-detail.toml`](examples/config/sarif-instance-detail.toml)
- [`examples/config/sarif-diff-ci-cd.toml`](examples/config/sarif-diff-ci-cd.toml)

## CI/CD examples

Prebuilt workflow examples:

- [GitHub Actions](workflows/github-actions.yml)
- [Buildkite](workflows/buildkite.yml)
- [GitLab CI](workflows/gitlab-ci.yml)
- [Bitbucket Pipelines](workflows/bitbucket-pipelines.yml)

Minimal pattern:

```yaml
- name: Run Socket CLI
  run: socketcli --config .socketcli.toml --target-path .
  env:
    SOCKET_SECURITY_API_TOKEN: ${{ secrets.SOCKET_SECURITY_API_TOKEN }}
```

## Common gotchas

See [`docs/troubleshooting.md`](docs/troubleshooting.md#common-gotchas).

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

- Full CLI reference: [`docs/cli-reference.md`](docs/cli-reference.md)
- CI/CD guide: [`docs/ci-cd.md`](docs/ci-cd.md)
- Troubleshooting guide: [`docs/troubleshooting.md`](docs/troubleshooting.md)
- Development guide: [`docs/development.md`](docs/development.md)
