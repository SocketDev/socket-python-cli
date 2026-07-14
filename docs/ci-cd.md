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

Use `--config .socketcli.toml` or `--config .socketcli.json` to keep pipeline commands small.

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

Equivalent JSON:

```json
{
  "socketcli": {
    "reach": true,
    "sarif_scope": "full",
    "sarif_grouping": "alert",
    "sarif_reachability": "reachable",
    "sarif_file": "results.sarif"
  }
}
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

#### Merge-base baselines in Buildkite (dynamic pipelines)

Notes for using `--base-commit-sha` (see the
[merge-base note in the CLI reference](cli-reference.md#pull-request-and-commit))
when your steps are emitted by a
[dynamic pipeline](https://buildkite.com/docs/pipelines/configure/dynamic-pipelines)
generator rather than a static YAML file:

- **Compute the merge base at generation time, not step time.** The generator runs
  with a full checkout; step agents may have shallow or fresh clones where
  `git merge-base` fails or needs an extra fetch. Resolve it once in the generator and
  bake it into the emitted step's `env`. Diff against the PR's *target* branch, which
  isn't always the default branch (see Buildkite's
  [environment variables](https://buildkite.com/docs/pipelines/configure/environment-variables)):

  ```shell
  TARGET="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-$BUILDKITE_PIPELINE_DEFAULT_BRANCH}"
  BASE_SHA=$(git merge-base "origin/${TARGET}" HEAD)
  ```

- **Emit the backfill step conditionally from the generator.** The generator is the
  natural place for the "does a baseline scan exist?" check
  (`GET /orgs/{org}/full-scans?repo=<repo>&commit_hash=$BASE_SHA&per_page=1`): only
  emit the baseline-scan step when it returns nothing. The emitted pipeline then shows
  in the UI whether a backfill will run.

- **Keep the backfill inside one command step.** The checkout-base → scan →
  checkout-PR sequence must not be split across steps — steps can land on different
  agents with different checkouts. Prefer
  [`git worktree`](https://git-scm.com/docs/git-worktree) over mutating the step's
  checkout: `git worktree add /tmp/socket-base "$BASE_SHA"` then
  `socketcli --target-path /tmp/socket-base --branch "$TARGET" --disable-blocking`.

- **Soft-fail infra errors, not findings.** A missing baseline (or any API error)
  exits with code 3 (`--exit-code-on-api-error` to change it); real findings exit 1.
  [`soft_fail: [{exit_status: 3}]`](https://buildkite.com/docs/pipelines/configure/step-types/command-step)
  on the PR scan step keeps infra errors from blocking merges while security findings
  still do.

- **["Cancel intermediate builds"](https://buildkite.com/docs/pipelines/configure/canceling-builds#cancel-running-intermediate-builds)
  on the default branch is the main source of baseline gaps.** Canceled builds never
  scan their commit, so merge-base lookups for PRs based on those commits fail. The
  conditional backfill step above is the remedy; there is no per-step exemption from
  build cancellation in Buildkite. If you need strict scan-once semantics for
  concurrent backfills of the same merge base, serialize the backfill step with a
  [concurrency group](https://buildkite.com/docs/pipelines/configure/workflows/controlling-concurrency)
  keyed on the merge-base SHA.

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

- `--strict-blocking` enables strict diff behavior (`new + unchanged`) for blocking evaluation and diff-based output selection.
- `--sarif-scope full` requires `--reach`.
- `--sarif-grouping alert` currently applies to `--sarif-scope full`.
- Diff-based SARIF can validly be empty when there are no matching net-new alerts.
- Keep API tokens in secret stores (`SOCKET_SECURITY_API_TOKEN`), not in config files.
