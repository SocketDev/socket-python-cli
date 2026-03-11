# Socket Security CLI: Full Reference

> This is the comprehensive reference document.  
> For first-time setup and common workflows, start with [`../README.md`](../README.md).

The Socket Security CLI was created to enable integrations with other tools like GitHub Actions, Buildkite, GitLab, Bitbucket, local use cases and more. The tool will get the head scan for the provided repo from Socket, create a new one, and then report any new alerts detected. If there are new alerts with blocking actions it'll exit with a non-Zero exit code.

## Quick Start

The CLI now features automatic detection of git repository information, making it much simpler to use in CI/CD environments. Most parameters are now optional and will be detected automatically from your git repository.

### Minimal Usage Examples

**GitHub Actions:**
```bash
socketcli --target-path $GITHUB_WORKSPACE --scm github --pr-number $PR_NUMBER
```

**Buildkite:**
```bash
socketcli --target-path ${BUILDKITE_BUILD_CHECKOUT_PATH:-.} --scm api --pr-number ${BUILDKITE_PULL_REQUEST:-0}
```

**GitLab CI:**
```bash
socketcli --target-path $CI_PROJECT_DIR --scm gitlab --pr-number ${CI_MERGE_REQUEST_IID:-0}
```

**Bitbucket Pipelines:**
```bash
socketcli --target-path $BITBUCKET_CLONE_DIR --scm api --pr-number ${BITBUCKET_PR_ID:-0}
```

**Local Development:**
```bash
socketcli --target-path ./my-project
```

The CLI will automatically detect:
- Repository name from git remote
- Branch name from git
- Commit SHA and message from git
- Committer information from git
- Default branch status from git and CI environment
- Changed files from git commit history

## CI/CD Workflow Examples

CI/CD-focused usage and platform examples are documented in [`ci-cd.md`](ci-cd.md).
Pre-configured workflow files are in [`../workflows/`](../workflows/).

## Monorepo Workspace Support

> **Note:** If you're looking to associate a scan with a named Socket workspace (e.g. because your repo is identified as `org/repo`), see the [`--workspace` flag](#repository) instead. The `--workspace-name` flag described in this section is an unrelated monorepo feature.

The Socket CLI supports scanning specific workspaces within monorepo structures while preserving git context from the repository root. This is useful for organizations that maintain multiple applications or services in a single repository.

### Key Features

- **Multiple Sub-paths**: Specify multiple `--sub-path` options to scan different directories within your monorepo
- **Combined Workspace**: All sub-paths are scanned together as a single workspace in Socket
- **Git Context Preserved**: Repository metadata (commits, branches, etc.) comes from the main target-path
- **Workspace Naming**: Use `--workspace-name` to differentiate scans from different parts of your monorepo

### Usage Examples

**Scan multiple frontend and backend workspaces:**
```bash
socketcli --target-path /path/to/monorepo \
          --sub-path frontend \
          --sub-path backend \
          --sub-path services/api \
          --workspace-name main-app
```

**GitHub Actions for monorepo workspace:**
```bash
socketcli --target-path $GITHUB_WORKSPACE \
          --sub-path packages/web \
          --sub-path packages/mobile \
          --workspace-name mobile-web \
          --scm github \
          --pr-number $PR_NUMBER
```

This will:
- Scan manifest files in `./packages/web/` and `./packages/mobile/`
- Combine them into a single workspace scan
- Create a repository in Socket named like `my-repo-mobile-web`
- Preserve git context (commits, branch info) from the repository root

**Generate GitLab Security Dashboard report:**
```bash
socketcli --enable-gitlab-security \
          --repo owner/repo \
          --target-path .
```

This will:
- Scan all manifest files in the current directory
- Generate a GitLab-compatible Dependency Scanning report
- Save to `gl-dependency-scanning-report.json`
- Include all actionable security alerts (error/warn level)

**Save SARIF report to file (e.g. for GitHub Code Scanning, SonarQube, or VS Code):**
```bash
socketcli --sarif-file results.sarif \
          --repo owner/repo \
          --target-path .
```

**Multiple output formats:**
```bash
socketcli --enable-json \
          --sarif-file results.sarif \
          --enable-gitlab-security \
          --repo owner/repo
```

This will simultaneously generate:
- JSON output to console
- SARIF report to `results.sarif` (and stdout)
- GitLab Security Dashboard report to `gl-dependency-scanning-report.json`

> **Note:** `--enable-sarif` prints SARIF to stdout only. Use `--sarif-file <path>` to save to a file (this also implies `--enable-sarif`). Use `--sarif-reachability` (requires `--reach` when not `all`) to filter by reachability state. Use `--sarif-scope diff|full` to choose between diff alerts (default) and full reachability facts scope. These flags are independent from `--enable-gitlab-security`, which produces a separate GitLab-specific Dependency Scanning report.
>
> In diff scope, `--strict-blocking` expands selection to include `new + unchanged` diff alerts for evaluation/output paths.
>
> SARIF scope examples:
> - Diff-only reachable findings: `socketcli --reach --sarif-file out.sarif --sarif-scope diff --sarif-reachability reachable`
> - Full reachability scope, reachable only: `socketcli --reach --sarif-file out.sarif --sarif-scope full --sarif-reachability reachable`
> - Full reachability scope, all reachability states: `socketcli --reach --sarif-file out.sarif --sarif-scope full`
> - Dashboard-style grouping (one result per alert key): `socketcli --reach --sarif-file out.sarif --sarif-scope full --sarif-grouping alert --sarif-reachability reachable`
>
> In `--sarif-scope full` mode with `--sarif-file`, SARIF JSON is written to file and stdout JSON is suppressed to avoid oversized CI logs.

### Requirements

- Both `--sub-path` and `--workspace-name` must be specified together
- `--sub-path` can be used multiple times to include multiple directories
- All specified sub-paths must exist within the target-path

## Usage

```` shell
socketcli [-h] [--api-token API_TOKEN] [--repo REPO] [--workspace WORKSPACE] [--repo-is-public] [--branch BRANCH] [--integration {api,github,gitlab,azure,bitbucket}]
          [--config <path>]
          [--owner OWNER] [--pr-number PR_NUMBER] [--commit-message COMMIT_MESSAGE] [--commit-sha COMMIT_SHA] [--committers [COMMITTERS ...]]
          [--target-path TARGET_PATH] [--sbom-file SBOM_FILE] [--license-file-name LICENSE_FILE_NAME] [--save-submitted-files-list SAVE_SUBMITTED_FILES_LIST]
          [--save-manifest-tar SAVE_MANIFEST_TAR] [--files FILES] [--sub-path SUB_PATH] [--workspace-name WORKSPACE_NAME]
          [--excluded-ecosystems EXCLUDED_ECOSYSTEMS] [--default-branch] [--pending-head] [--generate-license] [--enable-debug]
          [--enable-json] [--enable-sarif] [--sarif-file <path>] [--sarif-scope {diff,full}] [--sarif-grouping {instance,alert}] [--sarif-reachability {all,reachable,potentially,reachable-or-potentially}] [--enable-gitlab-security] [--gitlab-security-file <path>]
          [--disable-overview] [--exclude-license-details] [--allow-unverified] [--disable-security-issue]
          [--ignore-commit-files] [--disable-blocking] [--enable-diff] [--scm SCM] [--timeout TIMEOUT] [--include-module-folders]
          [--reach] [--reach-version REACH_VERSION] [--reach-timeout REACH_ANALYSIS_TIMEOUT]
          [--reach-memory-limit REACH_ANALYSIS_MEMORY_LIMIT] [--reach-ecosystems REACH_ECOSYSTEMS] [--reach-exclude-paths REACH_EXCLUDE_PATHS]
          [--reach-min-severity {low,medium,high,critical}] [--reach-skip-cache] [--reach-disable-analytics] [--reach-output-file REACH_OUTPUT_FILE]
          [--only-facts-file] [--version]
````

If you don't want to provide the Socket API Token every time then you can use the environment variable `SOCKET_SECURITY_API_TOKEN`

### Parameters

#### Authentication
| Parameter   | Required | Default | Description                                                                       |
|:------------|:---------|:--------|:----------------------------------------------------------------------------------|
| `--api-token` | False    |         | Socket Security API token (can also be set via SOCKET_SECURITY_API_TOKEN env var) |

#### Repository
| Parameter        | Required | Default | Description                                                                                                       |
|:-----------------|:---------|:--------|:------------------------------------------------------------------------------------------------------------------|
| `--repo`           | False    | *auto*  | Repository name in owner/repo format (auto-detected from git remote)                                             |
| `--workspace`      | False    |         | The Socket workspace to associate the scan with (e.g. `my-org` in `my-org/my-repo`). See note below.           |
| `--repo-is-public` | False    | False   | If set, flags a new repository creation as public. Defaults to false.                                            |
| `--integration`    | False    | api     | Integration type (api, github, gitlab, azure, bitbucket)                                                         |
| `--owner`          | False    |         | Name of the integration owner, defaults to the socket organization slug                                          |
| `--branch`         | False    | *auto*  | Branch name (auto-detected from git)                                                                             |
| `--committers`     | False    | *auto*  | Committer(s) to filter by (auto-detected from git commit)                                                        |

> **`--workspace` vs `--workspace-name`** — these are two distinct flags for different purposes:
>
> - **`--workspace <string>`** maps to the Socket API's `workspace` query parameter on `CreateOrgFullScan`. Use it when your repository belongs to a named Socket workspace (e.g. an org with multiple workspace groups). Example: `--repo my-repo --workspace my-org`. Without this flag, scans are created without workspace context and may not appear under the correct workspace in the Socket dashboard.
>
> - **`--workspace-name <string>`** is a monorepo feature. It appends a suffix to the repository slug to create a unique name in Socket (e.g. `my-repo-frontend`). It must always be paired with `--sub-path` and has nothing to do with the API `workspace` field. See [Monorepo Workspace Support](#monorepo-workspace-support) below.

#### Pull Request and Commit
| Parameter        | Required | Default | Description                                    |
|:-----------------|:---------|:--------|:-----------------------------------------------|
| `--pr-number`      | False    | "0"     | Pull request number                            |
| `--commit-message` | False    | *auto*  | Commit message (auto-detected from git)       |
| `--commit-sha`     | False    | *auto*  | Commit SHA (auto-detected from git)           |

#### Path and File
| Parameter                   | Required | Default               | Description                                                                                                                                                                      |
|:----------------------------|:---------|:----------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--target-path`               | False    | ./                    | Target path for analysis                                                                                                                                                         |
| `--sbom-file`                 | False    |                       | SBOM file path                                                                                                                                                                   |
| `--license-file-name`         | False    | `license_output.json` | Name of the file to save the license details to if enabled                                                                                                                       |
| `--save-submitted-files-list` | False    |                       | Save list of submitted file names to JSON file for debugging purposes                                                                                                            |
| `--save-manifest-tar`         | False    |                       | Save all manifest files to a compressed tar.gz archive with original directory structure                                                                                         |
| `--files`                     | False    | *auto*                | Files to analyze (JSON array string). Auto-detected from git commit changes when not specified                                                                                   |
| `--sub-path`                  | False    |                       | Sub-path within target-path for manifest file scanning (can be specified multiple times). All sub-paths are combined into a single workspace scan while preserving git context from target-path. Must be used with `--workspace-name` |
| `--workspace-name`            | False    |                       | Workspace name suffix to append to repository name (repo-name-workspace_name). Must be used with `--sub-path`                                                                     |
| `--excluded-ecosystems`       | False    | []                    | List of ecosystems to exclude from analysis (JSON array string). You can get supported files from the [Supported Files API](https://docs.socket.dev/reference/getsupportedfiles) |

#### Branch and Scan Configuration
| Parameter                | Required | Default | Description                                                                                           |
|:-------------------------|:---------|:--------|:------------------------------------------------------------------------------------------------------|
| `--default-branch`         | False    | *auto*  | Make this branch the default branch (auto-detected from git and CI environment when not specified)   |
| `--pending-head`           | False    | *auto*  | If true, the new scan will be set as the branch's head scan (automatically synced with default-branch) |
| `--include-module-folders` | False    | False   | If enabled will include manifest files from folders like node_modules                                |

#### Output Configuration
| Parameter                 | Required | Default | Description                                                                       |
|:--------------------------|:---------|:--------|:----------------------------------------------------------------------------------|
| `--generate-license`        | False    | False   | Generate license information                                                      |
| `--enable-debug`            | False    | False   | Enable debug logging                                                              |
| `--enable-json`             | False    | False   | Output in JSON format                                                             |
| `--enable-sarif`            | False    | False   | Enable SARIF output of results instead of table or JSON format (prints to stdout) |
| `--sarif-file`              | False    |         | Output file path for SARIF report (implies --enable-sarif). Use this to save SARIF output to a file for upload to GitHub Code Scanning, SonarQube, VS Code, or other SARIF-compatible tools |
| `--sarif-scope`             | False    | diff    | SARIF source scope: `diff` for net-new diff alerts, or `full` for full reachability facts scope (requires --reach for full) |
| `--sarif-grouping`          | False    | instance| SARIF grouping mode: `instance` (one entry per package/version/advisory instance) or `alert` (grouped alert-style output, full scope only) |
| `--sarif-reachability`      | False    | all     | SARIF reachability selector: `all`, `reachable`, `potentially`, or `reachable-or-potentially` (requires --reach when not `all`) |
| `--enable-gitlab-security`  | False    | False   | Enable GitLab Security Dashboard output format (Dependency Scanning report)       |
| `--gitlab-security-file`    | False    | gl-dependency-scanning-report.json | Output file path for GitLab Security report                |
| `--disable-overview`        | False    | False   | Disable overview output                                                           |
| `--exclude-license-details` | False    | False   | Exclude license details from the diff report (boosts performance for large repos) |
| `--version`                 | False    | False   | Show program's version number and exit                                            |

#### Security Configuration
| Parameter                | Required | Default | Description                   |
|:-------------------------|:---------|:--------|:------------------------------|
| `--allow-unverified`       | False    | False   | Allow unverified packages     |
| `--disable-security-issue` | False    | False   | Disable security issue checks |

#### Reachability Analysis
| Parameter                        | Required | Default | Description                                                                                                                |
|:---------------------------------|:---------|:--------|:---------------------------------------------------------------------------------------------------------------------------|
| `--reach`                          | False    | False   | Enable reachability analysis to identify which vulnerable functions are actually called by your code                       |
| `--reach-version`                  | False    | latest  | Version of @coana-tech/cli to use for analysis                                                                             |
| `--reach-timeout`                  | False    | 1200    | Timeout in seconds for the reachability analysis (default: 1200 seconds / 20 minutes)                                      |
| `--reach-memory-limit`             | False    | 4096    | Memory limit in MB for the reachability analysis (default: 4096 MB / 4 GB)                                                 |
| `--reach-concurrency`              | False    |         | Control parallel analysis execution (must be >= 1)                                                                         |
| `--reach-additional-params`        | False    |         | Pass custom parameters to the coana CLI tool                                                                               |
| `--reach-ecosystems`               | False    |         | Comma-separated list of ecosystems to analyze (e.g., "npm,pypi"). If not specified, all supported ecosystems are analyzed  |
| `--reach-exclude-paths`            | False    |         | Comma-separated list of file paths or patterns to exclude from reachability analysis                                       |
| `--reach-min-severity`             | False    |         | Minimum severity level for reporting reachability results (low, medium, high, critical)                                    |
| `--reach-skip-cache`               | False    | False   | Skip cache and force fresh reachability analysis                                                                           |
| `--reach-disable-analytics`        | False    | False   | Disable analytics collection during reachability analysis                                                                  |
| `--reach-output-file`              | False    | .socket.facts.json | Path where reachability analysis results should be saved                                                        |
| `--only-facts-file`                | False    | False   | Submit only the .socket.facts.json file to an existing scan (requires --reach and a prior scan)                            |

**Reachability Analysis Requirements:**
- `npm` - Required to install and run @coana-tech/cli
- `npx` - Required to execute @coana-tech/cli

## Config file support

Use `--config <path>` to load defaults from a `.toml` or `.json` file.
CLI arguments always take precedence over config file values.

Example `socketcli.toml`:

```toml
[socketcli]
repo = "example-repo"
reach = true
sarif_scope = "full"
sarif_grouping = "alert"
sarif_reachability = "reachable"
sarif_file = "reachable.sarif"
```

Equivalent `socketcli.json`:

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

Sample config files:
- [`../examples/config/sarif-dashboard-parity.toml`](../examples/config/sarif-dashboard-parity.toml)
- [`../examples/config/sarif-dashboard-parity.json`](../examples/config/sarif-dashboard-parity.json)
- [`../examples/config/sarif-instance-detail.toml`](../examples/config/sarif-instance-detail.toml)
- [`../examples/config/sarif-instance-detail.json`](../examples/config/sarif-instance-detail.json)
- [`../examples/config/sarif-diff-ci-cd.toml`](../examples/config/sarif-diff-ci-cd.toml)
- [`../examples/config/sarif-diff-ci-cd.json`](../examples/config/sarif-diff-ci-cd.json)

### CI/CD usage tips

For CI-specific examples and guidance, see [`ci-cd.md`](ci-cd.md).

The CLI will automatically install `@coana-tech/cli` if not present. Use `--reach` to enable reachability analysis during a full scan, or use `--only-facts-file` with `--reach` to submit reachability results to an existing scan.

#### Advanced Configuration
| Parameter                | Required | Default | Description                                                           |
|:-------------------------|:---------|:--------|:----------------------------------------------------------------------|
| `--ignore-commit-files`    | False    | False   | Ignore commit files                                                   |
| `--disable-blocking`       | False    | False   | Disable blocking mode                                                 |
| `--strict-blocking`        | False    | False   | Fail on ANY security policy violations (blocking severity), not just new ones. Only works in diff mode. See [Strict Blocking Mode](#strict-blocking-mode) for details. |
| `--enable-diff`            | False    | False   | Enable diff mode even when using `--integration api` (forces diff mode without SCM integration) |
| `--scm`                    | False    | api     | Source control management type                                        |
| `--timeout`                | False    |         | Timeout in seconds for API requests                                   |

#### Plugins

The Python CLI currently supports the following plugins:

- Jira
- Slack

##### Jira

| Environment Variable    | Required | Default | Description                        |
|:------------------------|:---------|:--------|:-----------------------------------|
| `SOCKET_JIRA_ENABLED`     | False    | false   | Enables/Disables the Jira Plugin   |
| `SOCKET_JIRA_CONFIG_JSON` | True     | None    | Required if the Plugin is enabled. |

Example `SOCKET_JIRA_CONFIG_JSON` value

````json
{"url": "https://REPLACE_ME.atlassian.net", "email": "example@example.com", "api_token": "REPLACE_ME", "project": "REPLACE_ME" }
````

##### Slack

| Environment Variable     | Required | Default | Description                        |
|:-------------------------|:---------|:--------|:-----------------------------------|
| `SOCKET_SLACK_CONFIG_JSON` | False    | None    | Slack configuration (enables plugin when set). Supports webhook or bot mode. Alternatively, use `--slack-webhook` for simple webhook mode. |
| `SOCKET_SLACK_BOT_TOKEN`   | False    | None    | Slack Bot User OAuth Token (starts with `xoxb-`). Required when using bot mode. |

**Slack supports two modes:**

1. **Webhook Mode** (default): Posts to incoming webhooks
2. **Bot Mode**: Posts via Slack API with bot token authentication

###### Webhook Mode Examples

Simple webhook:

````json
{"url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}
````

Multiple webhooks with advanced filtering:

````json
{
  "mode": "webhook",
  "url": [
    {
      "name": "prod_alerts",
      "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    },
    {
      "name": "critical_only",
      "url": "https://hooks.slack.com/services/YOUR/OTHER/WEBHOOK/URL"
    }
  ],
  "url_configs": {
    "prod_alerts": {
      "reachability_alerts_only": true,
      "severities": ["high", "critical"]
    },
    "critical_only": {
      "severities": ["critical"]
    }
  }
}
````

###### Bot Mode Examples

**Setting up a Slack Bot:**
1. Go to https://api.slack.com/apps and create a new app
2. Under "OAuth & Permissions", add the `chat:write` bot scope
3. Install the app to your workspace and copy the "Bot User OAuth Token"
4. Invite the bot to your channels: `/invite @YourBotName`

Basic bot configuration:

````json
{
  "mode": "bot",
  "bot_configs": [
    {
      "name": "security_alerts",
      "channels": ["security-alerts", "dev-team"]
    }
  ]
}
````

Bot with filtering (reachability-only alerts):

````json
{
  "mode": "bot",
  "bot_configs": [
    {
      "name": "critical_reachable",
      "channels": ["security-critical"],
      "severities": ["critical", "high"],
      "reachability_alerts_only": true
    },
    {
      "name": "all_alerts",
      "channels": ["security-all"],
      "repos": ["myorg/backend", "myorg/frontend"]
    }
  ]
}
````

Set the bot token:
```bash
export SOCKET_SLACK_BOT_TOKEN="xoxb-your-bot-token-here"
```

**Configuration Options:**

Webhook mode (`url_configs`):
- `reachability_alerts_only` (boolean, default: false): When `--reach` is enabled, only send reachable vulnerabilities from the selected diff alert set (uses reachability facts when available; otherwise falls back to blocking-status behavior)
- `repos` (array): Only send alerts for specific repositories (e.g., `["owner/repo1", "owner/repo2"]`)
- `alert_types` (array): Only send specific alert types (e.g., `["malware", "typosquat"]`)
- `severities` (array): Only send alerts with specific severities (e.g., `["high", "critical"]`)

Bot mode (`bot_configs` array items):
- `name` (string, required): Friendly name for this configuration
- `channels` (array, required): Channel names (without #) where alerts will be posted
- `severities` (array, optional): Only send alerts with specific severities (e.g., `["high", "critical"]`)
- `repos` (array, optional): Only send alerts for specific repositories
- `alert_types` (array, optional): Only send specific alert types
- `reachability_alerts_only` (boolean, default: false): Only send reachable vulnerabilities when using `--reach`

## Strict Blocking Mode

The `--strict-blocking` flag enforces a zero-tolerance security policy by failing builds when **ANY** security violations with blocking severity exist, not just new ones introduced in the current changes.

### Standard vs Strict Blocking Behavior

**Standard Behavior (Default)**:
- ✅ Passes if no NEW violations are introduced
- ❌ Fails only on NEW violations from your changes
- 🟡 Existing violations are ignored

**Strict Blocking Behavior (`--strict-blocking`)**:
- ✅ Passes only if NO violations exist (new or existing)
- ❌ Fails on ANY violation (new OR existing)
- 🔴 Enforces zero-tolerance policy

### Usage Examples

**Basic strict blocking:**
```bash
socketcli --target-path ./my-project --strict-blocking
```

**In GitHub Actions:**
```bash
socketcli --target-path $GITHUB_WORKSPACE --scm github --pr-number $PR_NUMBER --strict-blocking
```

**In Buildkite:**
```bash
socketcli --target-path ${BUILDKITE_BUILD_CHECKOUT_PATH:-.} --scm api --pr-number ${BUILDKITE_PULL_REQUEST:-0} --strict-blocking
```

**In GitLab CI:**
```bash
socketcli --target-path $CI_PROJECT_DIR --scm gitlab --pr-number ${CI_MERGE_REQUEST_IID:-0} --strict-blocking
```

### Output Differences

**Standard scan output:**
```
Security issues detected by Socket Security:
  - NEW blocking issues: 2
  - NEW warning issues: 1
```

**Strict blocking scan output:**
```
Security issues detected by Socket Security:
  - NEW blocking issues: 2
  - NEW warning issues: 1
  - EXISTING blocking issues: 5 (causing failure due to --strict-blocking)
  - EXISTING warning issues: 3
```

### Use Cases

1. **Zero-Tolerance Security Policy**: Enforce that no security violations exist in your codebase at any time
2. **Gradual Security Improvement**: Use alongside standard scans to monitor existing violations while blocking new ones
3. **Protected Branch Enforcement**: Require all violations to be resolved before merging to main/production
4. **Security Audits**: Scheduled scans that fail if any violations accumulate

### Important Notes

- **Diff Mode Only**: The flag only works in diff mode (with SCM integration). In API mode, a warning is logged.
- **Error-Level Only**: Only fails on `error=True` alerts (blocking severity), not warnings.
- **Priority**: `--disable-blocking` takes precedence - if both flags are set, the build will always pass.
- **First Scan**: On the very first scan of a repository, there are no "existing" violations, so behavior is identical to standard mode.

### Flag Combinations

**Strict blocking with debugging:**
```bash
socketcli --strict-blocking --enable-debug
```

**Strict blocking with JSON output:**
```bash
socketcli --strict-blocking --enable-json > security-report.json
```

**Override for testing** (passes even with violations):
```bash
socketcli --strict-blocking --disable-blocking
```

### Migration Strategy

**Phase 1: Assessment** - Add strict scan with `allow_failure: true` in CI
**Phase 2: Remediation** - Fix or triage all violations
**Phase 3: Enforcement** - Set `allow_failure: false` to block merges

For CI/CD-oriented strict-blocking examples, see [`ci-cd.md`](ci-cd.md).

## Automatic Git Detection

The CLI now automatically detects repository information from your git environment, significantly simplifying usage in CI/CD pipelines:

### Auto-Detected Information

- **Repository name**: Extracted from git remote origin URL
- **Branch name**: Current git branch or CI environment variables
- **Commit SHA**: Latest commit hash or CI-provided commit SHA
- **Commit message**: Latest commit message
- **Committer information**: Git commit author details
- **Default branch status**: Determined from git repository and CI environment
- **Changed files**: Files modified in the current commit (for differential scanning)
> **Note on merge commits**:  
> Standard merges (two parents) are supported.  
> For *octopus merges* (three or more parents), Git only reports changes relative to the first parent. This can lead to incomplete or empty file lists if changes only exist relative to other parents. In these cases, differential scanning may be skipped. To ensure coverage, use `--ignore-commit-files` to force a full scan or specify files explicitly with `--files`.
### Default Branch Detection

The CLI uses intelligent default branch detection with the following priority:

1. **Explicit `--default-branch` flag**: Takes highest priority when specified
2. **CI environment detection**: Uses CI platform variables (GitHub Actions, GitLab CI, and Bitbucket Pipelines)
3. **Git repository analysis**: Compares current branch with repository's default branch
4. **Fallback**: Defaults to `false` if none of the above methods succeed

Both `--default-branch` and `--pending-head` parameters are automatically synchronized to ensure consistent behavior.

## GitLab Token Configuration

GitLab token/auth behavior and CI examples are documented in [`ci-cd.md`](ci-cd.md).

## File Selection Behavior

The CLI determines which files to scan based on the following logic:

1. **Git Commit Files (Default)**: The CLI automatically checks files changed in the current git commit. If any of these files match supported manifest patterns (like package.json, requirements.txt, etc.), a scan is triggered.

2. **`--files` Parameter Override**: When specified, this parameter takes precedence over git commit detection. It accepts a JSON array of file paths to check for manifest files.

3. **`--ignore-commit-files` Flag**: When set, git commit files are ignored completely, and the CLI will scan all manifest files in the target directory regardless of what changed.

4. **Automatic Fallback**: If no manifest files are found in git commit changes and no `--files` are specified, the CLI automatically switches to "API mode" and performs a full repository scan.

> **Important**: The CLI doesn't scan only the specified files - it uses them to determine whether a scan should be performed and what type of scan to run. When triggered, it searches the entire `--target-path` for all supported manifest files.

### Scanning Modes

- **Differential Mode**: When manifest files are detected in changes, performs a diff scan with PR/MR comment integration
- **API Mode**: When no manifest files are in changes, creates a full scan report without PR comments but still scans the entire repository
- **Force Mode**: With `--ignore-commit-files`, always performs a full scan regardless of changes
- **Forced Diff Mode**: With `--enable-diff`, forces differential mode even when using `--integration api` (without SCM integration)

### Examples

- **Commit with manifest file**: If your commit includes changes to `package.json`, a differential scan will be triggered automatically with PR comment integration.
- **Commit without manifest files**: If your commit only changes non-manifest files (like `.github/workflows/socket.yaml`), the CLI automatically switches to API mode and performs a full repository scan.
- **Using `--files`**: If you specify `--files '["package.json"]'`, the CLI will check if this file exists and is a manifest file before determining scan type.
- **Using `--ignore-commit-files`**: This forces a full scan of all manifest files in the target path, regardless of what's in your commit.
- **Using `--enable-diff`**: Forces diff mode without SCM integration - useful when you want differential scanning but are using `--integration api`. For example: `socketcli --integration api --enable-diff --target-path /path/to/repo`
- **Auto-detection**: Most CI/CD scenarios now work with just `socketcli --target-path /path/to/repo --scm github --pr-number $PR_NUM`

## Troubleshooting

Troubleshooting and debugging workflows are documented in [`troubleshooting.md`](troubleshooting.md).

## GitLab Security Dashboard Integration

Socket CLI can generate reports compatible with GitLab's Security Dashboard, allowing vulnerability information to be displayed directly in merge requests and security dashboards. This feature complements the existing [Socket GitLab integration](https://docs.socket.dev/docs/gitlab) by providing standardized dependency scanning reports.

### Generating GitLab Security Reports

To generate a GitLab-compatible security report:

```bash
socketcli --enable-gitlab-security --repo owner/repo
```

This creates a `gl-dependency-scanning-report.json` file following GitLab's Dependency Scanning report schema.

### GitLab CI/CD Integration

Add Socket Security scanning to your GitLab CI pipeline to generate Security Dashboard reports:

```yaml
# .gitlab-ci.yml
socket_security_scan:
  stage: security
  image: python:3.11
  before_script:
    - pip install socketsecurity
  script:
    - socketcli
        --api-token $SOCKET_API_TOKEN
        --repo $CI_PROJECT_PATH
        --branch $CI_COMMIT_REF_NAME
        --commit-sha $CI_COMMIT_SHA
        --enable-gitlab-security
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - gl-dependency-scanning-report.json
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

**Note**: This Security Dashboard integration can be used alongside the [Socket GitLab App](https://docs.socket.dev/docs/gitlab) for comprehensive protection:
- **Socket GitLab App**: Real-time PR comments, policy enforcement, and blocking
- **Security Dashboard**: Centralized vulnerability tracking and reporting in GitLab's native interface

### Custom Output Path

Specify a custom output path for the GitLab security report:

```bash
socketcli --enable-gitlab-security --gitlab-security-file custom-path.json
```

### Multiple Output Formats

GitLab security reports can be generated alongside other output formats:

```bash
socketcli --enable-json --enable-gitlab-security --sarif-file results.sarif
```

This command will:
- Output JSON format to console
- Save GitLab Security Dashboard report to `gl-dependency-scanning-report.json`
- Save SARIF report to `results.sarif`

### Security Dashboard Features

The GitLab Security Dashboard will display:
- **Vulnerability Severity**: Critical, High, Medium, Low levels
- **Affected Packages**: Package name, version, and ecosystem
- **CVE Identifiers**: Direct links to CVE databases when available
- **Dependency Chains**: Distinction between direct and transitive dependencies
- **Remediation Suggestions**: Fix recommendations from Socket Security
- **Alert Categories**: Supply chain risks, malware, vulnerabilities, and more

### Alert Filtering

The GitLab report includes **actionable security alerts** based on your Socket policy configuration:

**Included Alerts** ✅:
- **Error-level alerts** (`error: true`) - Security policy violations that block merges
- **Warning-level alerts** (`warn: true`) - Important security concerns requiring attention

**Excluded Alerts** ❌:
- **Ignored alerts** (`ignore: true`) - Alerts explicitly ignored in your policy
- **Monitor-only alerts** (`monitor: true` without error/warn) - Tracked but not actionable

**Socket Alert Types Detected**:
- Supply chain risks (malware, typosquatting, suspicious behavior)
- Security vulnerabilities (CVEs, unsafe code patterns)
- Risky permissions (network access, filesystem access, shell access)
- License policy violations

All alert types are included in the GitLab report if they're marked as `error` or `warn` by your Socket Security policy, ensuring the Security Dashboard shows only actionable findings.

### Report Schema

Socket CLI generates reports compliant with [GitLab Dependency Scanning schema version 15.0.0](https://docs.gitlab.com/ee/development/integrations/secure.html). The reports include:

- **Scan metadata**: Analyzer and scanner information
- **Vulnerabilities**: Detailed vulnerability data with:
  - Unique deterministic UUIDs for tracking
  - Package location and dependency information
  - Severity levels mapped from Socket's analysis
  - Socket-specific alert types and CVE identifiers
  - Links to Socket.dev for detailed analysis

### Requirements

- **GitLab Version**: GitLab 12.0 or later (for Security Dashboard support)
- **Socket API Token**: Set via `$SOCKET_API_TOKEN` environment variable or `--api-token` parameter
- **CI/CD Artifacts**: Reports must be uploaded as `dependency_scanning` artifacts

### Troubleshooting

**Report not appearing in Security Dashboard:**
- Verify the artifact is correctly configured in `.gitlab-ci.yml`
- Check that the job succeeded and artifacts were uploaded
- Ensure the report file follows the correct schema format

**Empty vulnerabilities array:**
- This is normal if no new security issues were detected
- Check Socket.dev dashboard for full analysis details

## Development

Developer setup, workflows, and contributor notes are documented in [`development.md`](development.md).
