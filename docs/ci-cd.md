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

#### GitHub Actions: scan changed monorepo workspaces independently

GitHub Actions `paths` filters only decide whether a workflow starts. They do not
change `socketcli` discovery or upload scope. For a merge gate, it is usually safer
to start a small selector job on every PR update, then create one scan job per
affected logical workspace. This also avoids a required check remaining pending
when GitHub skips the entire workflow because of a top-level path filter.

Define a repository variable named `SOCKET_MONOREPO_WORKSPACES_JSON`. Its value is
an array with one stable workspace name, one or more scan roots, and the path globs
that should select that workspace. Fill these placeholders with the repository's
real layout; list a shared/root lockfile in every workspace it affects.

```json
[
  {
    "name": "<stable-workspace-name>",
    "sub_paths": ["<repo-relative-scan-root>"],
    "watch_globs": ["<repo-relative-changed-file-glob>"]
  }
]
```

Also define `SOCKETCLI_VERSION` as the exact package version validated for the
workflow. The workflow below logs that version, uses full Git history for reliable
base/head selection, creates one matrix job (and therefore one graph and baseline)
per selected workspace, and fails closed on CLI/API/timeout failures. It uses API
SCM mode plus `--enable-diff` because parallel `--scm github` jobs can race while
updating the same PR comments; the matrix checks and report links are the gate.

```yaml
name: Socket Security

on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  select-workspaces:
    runs-on: ubuntu-latest
    outputs:
      count: ${{ steps.select.outputs.count }}
      matrix: ${{ steps.select.outputs.matrix }}
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
          persist-credentials: false

      - id: select
        name: Select changed workspaces
        env:
          WORKSPACES_JSON: ${{ vars.SOCKET_MONOREPO_WORKSPACES_JSON }}
          BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
        shell: bash
        run: |
          python - <<'PY'
          import fnmatch
          import json
          import os
          import re
          import subprocess

          workspaces = json.loads(os.environ["WORKSPACES_JSON"])
          if not isinstance(workspaces, list):
              raise SystemExit("SOCKET_MONOREPO_WORKSPACES_JSON must be a JSON array")

          base = os.environ["BASE_SHA"]
          head = os.environ["HEAD_SHA"]
          if not base or set(base) == {"0"}:
              base = subprocess.check_output(
                  ["git", "rev-parse", f"{head}^"], text=True
              ).strip()
          changed_output = subprocess.check_output(
              ["git", "diff", "--name-only", "-z", base, head]
          )
          changed = [
              item.decode("utf-8", "surrogateescape")
              for item in changed_output.split(b"\0")
              if item
          ]

          selected = []
          for workspace in workspaces:
              name = workspace.get("name", "")
              sub_paths = workspace.get("sub_paths") or []
              watch_globs = workspace.get("watch_globs") or []
              if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                  raise SystemExit(f"Invalid workspace name: {name!r}")
              if not sub_paths or any(
                  not isinstance(path, str)
                  or path.startswith("/")
                  or ".." in path.split("/")
                  for path in sub_paths
              ):
                  raise SystemExit(f"Invalid sub_paths for workspace {name!r}")
              if not watch_globs:
                  watch_globs = [
                      pattern
                      for path in sub_paths
                      for pattern in (
                          ["*"]
                          if path.strip("/") in ("", ".")
                          else [path.rstrip("/"), f"{path.rstrip('/')}/*"]
                      )
                  ]
              if any(
                  fnmatch.fnmatchcase(path, pattern)
                  for path in changed
                  for pattern in watch_globs
              ):
                  selected.append({"name": name, "sub_paths": sub_paths})

          matrix = json.dumps({"include": selected}, separators=(",", ":"))
          with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
              output.write(f"count={len(selected)}\n")
              output.write(f"matrix={matrix}\n")
          PY

  scan-workspace:
    needs: select-workspaces
    if: needs.select-workspaces.outputs.count != '0'
    timeout-minutes: 20
    strategy:
      fail-fast: false
      matrix: ${{ fromJSON(needs.select-workspaces.outputs.matrix) }}
    name: Socket scan (${{ matrix.name }})
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
          persist-credentials: false

      - uses: actions/setup-python@v6
        with:
          python-version: '3.12'

      - name: Install pinned Socket CLI
        env:
          SOCKETCLI_VERSION: ${{ vars.SOCKETCLI_VERSION }}
        run: |
          python -m pip install "socketsecurity==$SOCKETCLI_VERSION"
          socketcli --version

      - name: Scan workspace
        env:
          SOCKET_SECURITY_API_KEY: ${{ secrets.SOCKET_SECURITY_API_KEY }}
          PR_NUMBER: ${{ github.event.pull_request.number || 0 }}
          WORKSPACE_NAME: ${{ matrix.name }}
          SUB_PATHS_JSON: ${{ toJSON(matrix.sub_paths) }}
        shell: bash
        run: |
          set +e
          args=(
            --target-path "$GITHUB_WORKSPACE"
            --workspace-name "$WORKSPACE_NAME"
            --enable-diff
            --pr-number "$PR_NUMBER"
            --exit-code-on-api-error 3
            --report-link-file socket-report-link.txt
            --summary-file socket-summary.txt
          )
          while IFS= read -r sub_path; do
            args+=(--sub-path "$sub_path")
          done < <(jq -r '.[]' <<<"$SUB_PATHS_JSON")

          socketcli "${args[@]}" 2>&1 | tee socket-output.log
          code=${PIPESTATUS[0]}

          {
            echo "## Socket scan: $WORKSPACE_NAME"
            if [ -s socket-report-link.txt ]; then
              echo "[View the report]($(cat socket-report-link.txt))"
            fi
            if [ -s socket-summary.txt ]; then
              echo '```'
              cat socket-summary.txt
              echo '```'
            fi
          } >> "$GITHUB_STEP_SUMMARY"

          exit "$code"

  socket-security:
    if: always()
    needs: [select-workspaces, scan-workspace]
    runs-on: ubuntu-latest
    steps:
      - name: Enforce matrix result
        env:
          SELECT_RESULT: ${{ needs.select-workspaces.result }}
          SCAN_RESULT: ${{ needs.scan-workspace.result }}
        run: |
          test "$SELECT_RESULT" = success
          [[ "$SCAN_RESULT" = success || "$SCAN_RESULT" = skipped ]]
```

Each configuration object may intentionally contain several `sub_paths` when
those directories are one logical dependency graph. To split backend resolution,
use separate objects with different `name` values. Add `--workspace <name>` only
when the Socket organization requires API workspace association; it is not a scan
scope control.

The job has an explicit 20-minute total budget. Tune that value from observed
workspace-level latency after the split; a five-minute cap can still be too close
to a slow request plus local startup. The CLI's `--timeout` is different: it
defaults to 1,200 seconds **per API request**. If an operator adds GNU `timeout`,
that process supervisor can terminate the CLI before it maps an error through
`--exit-code-on-api-error`; without `--preserve-status`, GNU reports 124 after its
initial timeout signal or 137 if `SIGKILL` is involved.

### Buildkite

```yaml
steps:
  - label: "Socket scan"
    command: "socketcli --config .socketcli.toml --target-path ."
    env:
      SOCKET_SECURITY_API_TOKEN: "${SOCKET_SECURITY_API_TOKEN}"
```

The CLI reads Buildkite's native `BUILDKITE_COMMIT`, `BUILDKITE_BRANCH`,
`BUILDKITE_PULL_REQUEST`, and `BUILDKITE_PULL_REQUEST_BASE_BRANCH` variables.
For pull-request builds, ensure the checkout contains the base branch and the
checked-out head commit. The CLI uses those local refs first and performs a
targeted fetch only when a required ref or its comparison history is missing;
it does not fetch every remote ref and tag during startup.

When `--scm github` is used from Buildkite, the CLI also derives GitHub comment
context from `BUILDKITE_REPO`, `BUILDKITE_BUILD_CHECKOUT_PATH`, and the variables
above. Set `GH_API_TOKEN` to a GitHub token with the required repository access.
GitHub Enterprise users should also set `GITHUB_API_URL`; GitHub.com defaults to
`https://api.github.com`.

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
