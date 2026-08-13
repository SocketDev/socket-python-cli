# CI/CD guide

Use this guide for pipeline-focused CLI usage across platforms.

The shell commands in the recommended patterns are CI-provider neutral. Buildkite
pipeline equivalents and provider-specific considerations are called out alongside
the relevant guidance below.

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

### Buildkite: retain SARIF as a build artifact

Either recommended pattern can run directly in a Buildkite command step. When the
scan writes SARIF, add
[`artifact_paths`](https://buildkite.com/docs/pipelines/configure/artifacts#upload-artifacts-with-a-command-step)
so developers can download the report from the build after the command finishes:

```yaml
steps:
  - label: ":socket: Socket reachable diff"
    command: |
      socketcli \
        --reach \
        --sarif-file results.sarif \
        --sarif-scope diff \
        --sarif-reachability reachable \
        --strict-blocking
    artifact_paths:
      - "results.sarif"
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

The Buildkite examples below use the same checked-in `.socketcli.toml` file; no
Buildkite-specific config-file format is required.

## Platform examples

### GitHub Actions

```yaml
- name: Run Socket CLI
  run: socketcli --config .socketcli.toml --target-path .
  env:
    SOCKET_SECURITY_API_TOKEN: ${{ secrets.SOCKET_SECURITY_API_TOKEN }}
```

### Buildkite

This example assumes a GitHub-hosted repository. Change
`SOCKET_SCM_INTEGRATION` to `gitlab` for a GitLab-hosted repository, or `api`
when provider association is not wanted. The doubled dollar signs defer
Buildkite variable expansion until the command runs on an agent.

```yaml
env:
  SOCKET_SCM_INTEGRATION: "github"

steps:
  - label: "Socket scan"
    command: |
      socketcli \
        --config .socketcli.toml \
        --target-path . \
        --integration "$${SOCKET_SCM_INTEGRATION:-api}" \
        --pr-number "$${BUILDKITE_PULL_REQUEST:-0}"
    secrets:
      - SOCKET_SECURITY_API_TOKEN
```

The `secrets` block expects a
[Buildkite secret](https://buildkite.com/docs/pipelines/security/secrets/buildkite-secrets)
named `SOCKET_SECURITY_API_TOKEN`. If your organization uses an external secrets
plugin or an agent hook instead, remove that block and inject the same environment
variable through your existing mechanism. Do not store the token in pipeline YAML.

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

### Azure Pipelines

```yaml
- script: |
    socketcli \
      --integration azure \
      --enable-diff \
      --target-path "$(Build.SourcesDirectory)"
  env:
    SOCKET_SECURITY_API_TOKEN: $(SOCKET_SECURITY_API_TOKEN)
```

### Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        script:
          - socketcli --config .socketcli.toml --target-path .
```

## Pull request and Dashboard association

The CLI sends the resolved pull request number with each full scan and attaches
the pull request URL to diff scans so the Socket Dashboard can associate the
report with its originating change. If `--pr-number` is supplied, it wins;
passing `--pr-number 0` explicitly disables automatic association.

Without an explicit value, the CLI recognizes:

- GitHub Actions: `PR_NUMBER`, then the PR number in `GITHUB_REF`.
- GitLab CI: `CI_MERGE_REQUEST_IID`.
- Azure Pipelines: `SYSTEM_PULLREQUEST_PULLREQUESTNUMBER` for GitHub-hosted
  repositories, otherwise `SYSTEM_PULLREQUEST_PULLREQUESTID` for Azure Repos.

### Buildkite PR context

Buildkite is SCM-provider neutral, so the CLI does not infer a provider or consume
its PR variable automatically. Pass Buildkite's
[`BUILDKITE_PULL_REQUEST`](https://buildkite.com/docs/pipelines/configure/environment-variables#BUILDKITE_PULL_REQUEST)
value to
`--pr-number` and identify the repository host with `--integration`, as shown in
the Buildkite platform example above. Buildkite sets `BUILDKITE_PULL_REQUEST` to
`false` outside PR builds; the CLI treats that value as no PR.

Use `--integration github` for GitHub-hosted repositories and `--integration gitlab`
for GitLab-hosted ones. In both cases the CLI reads the repository slug and host from
[`BUILDKITE_REPO`](https://buildkite.com/docs/pipelines/configure/environment-variables#BUILDKITE_REPO)
to build the pull request or merge request link, so github.com, GitLab.com, and
self-hosted installations all work without extra configuration. Setting
`CI_PROJECT_URL` still overrides the derived GitLab project URL. Keep `--scm api`
unless you also intend to configure an existing GitHub or GitLab comment adapter and
its provider token.

`--scm github` and `--scm gitlab` also imply the matching scan integration for
Dashboard metadata unless `--integration` was explicitly supplied. PR comments
remain limited to the existing GitHub and GitLab SCM adapters; Azure receives
console output and Dashboard association but does not post a PR comment.

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
- In Buildkite pipeline YAML, follow its
  [runtime interpolation](https://buildkite.com/docs/pipelines/configure/environment-variables#runtime-variable-interpolation)
  guidance and use `$$` for variables that must expand when the command runs rather
  than when the pipeline is uploaded.
- Security findings with `props.firstPatchedVersionIdentifier` show that value in
  the console table, including native Buildkite job logs, and in GitHub/GitLab
  security comments when that SCM adapter is configured. Findings without a known
  patched release leave the console cell blank and omit the comment field.
