# CI/CD guide

Use this guide for pipeline-focused CLI usage across platforms.

## Recommended patterns

### Dashboard-style reachable SARIF

```bash
socketcli \
  --reach \
  --sarif-file results.sarif \
  --sarif-scope full \
  --sarif-grouping alert \
  --sarif-reachability reachable \
  --disable-blocking
```

### Diff-based gating on new reachable findings

```bash
socketcli \
  --reach \
  --sarif-file results.sarif \
  --sarif-scope diff \
  --sarif-reachability reachable \
  --strict-blocking
```

## Config file usage in CI

Use `--config .socketcli.toml` to keep pipeline commands small.

Precedence order:

`CLI flags` > `environment variables` > `config file` > `built-in defaults`

Example:

```toml
[socketcli]
reach = true
sarif_scope = "full"
sarif_grouping = "alert"
sarif_reachability = "reachable"
sarif_file = "results.sarif"
```

## Platform examples

### GitHub Actions

```yaml
- name: Run Socket CLI
  run: socketcli --config .socketcli.toml --target-path .
  env:
    SOCKET_SECURITY_API_TOKEN: ${{ secrets.SOCKET_SECURITY_API_TOKEN }}
```

### Buildkite

```yaml
steps:
  - label: "Socket scan"
    command: "socketcli --config .socketcli.toml --target-path ."
    env:
      SOCKET_SECURITY_API_TOKEN: "${SOCKET_SECURITY_API_TOKEN}"
```

### GitLab CI

```yaml
socket_scan:
  script:
    - socketcli --config .socketcli.toml --target-path .
  variables:
    SOCKET_SECURITY_API_TOKEN: $SOCKET_SECURITY_API_TOKEN
```

### Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        script:
          - socketcli --config .socketcli.toml --target-path .
```

## Workflow templates

Prebuilt examples in this repo:

- [`../workflows/github-actions.yml`](../workflows/github-actions.yml)
- [`../workflows/buildkite.yml`](../workflows/buildkite.yml)
- [`../workflows/gitlab-ci.yml`](../workflows/gitlab-ci.yml)
- [`../workflows/bitbucket-pipelines.yml`](../workflows/bitbucket-pipelines.yml)

## CI gotchas

- `--strict-blocking` changes pass/fail policy, not SARIF dataset semantics.
- `--sarif-scope full` requires `--reach`.
- `--sarif-grouping alert` currently applies to `--sarif-scope full`.
- Diff-based SARIF can validly be empty when there are no matching net-new alerts.
- Keep API tokens in secret stores (`SOCKET_SECURITY_API_TOKEN`), not in config files.
