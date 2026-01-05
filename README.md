# Socket Security CLI

The Socket Security CLI was created to enable integrations with other tools like GitHub Actions, GitLab, BitBucket, local use cases and more. The tool will get the head scan for the provided repo from Socket, create a new one, and then report any new alerts detected. If there are new alerts with blocking actions it'll exit with a non-Zero exit code.

## Quick Start

The CLI now features automatic detection of git repository information, making it much simpler to use in CI/CD environments. Most parameters are now optional and will be detected automatically from your git repository.

### Minimal Usage Examples

**GitHub Actions:**
```bash
socketcli --target-path $GITHUB_WORKSPACE --scm github --pr-number $PR_NUMBER
```

**GitLab CI:**
```bash
socketcli --target-path $CI_PROJECT_DIR --scm gitlab --pr-number ${CI_MERGE_REQUEST_IID:-0}
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

Pre-configured workflow examples are available in the [`workflows/`](workflows/) directory:

- **[GitHub Actions](workflows/github-actions.yml)** - Complete workflow with concurrency control and automatic PR detection
- **[GitLab CI](workflows/gitlab-ci.yml)** - Pipeline configuration with caching and environment variable handling  
- **[Bitbucket Pipelines](workflows/bitbucket-pipelines.yml)** - Basic pipeline setup with optional path filtering

These examples are production-ready and include best practices for each platform.

## Monorepo Workspace Support

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

### Requirements

- Both `--sub-path` and `--workspace-name` must be specified together
- `--sub-path` can be used multiple times to include multiple directories
- All specified sub-paths must exist within the target-path

## Usage

```` shell
socketcli [-h] [--api-token API_TOKEN] [--repo REPO] [--repo-is-public] [--branch BRANCH] [--integration {api,github,gitlab,azure,bitbucket}] 
          [--owner OWNER] [--pr-number PR_NUMBER] [--commit-message COMMIT_MESSAGE] [--commit-sha COMMIT_SHA] [--committers [COMMITTERS ...]] 
          [--target-path TARGET_PATH] [--sbom-file SBOM_FILE] [--license-file-name LICENSE_FILE_NAME] [--save-submitted-files-list SAVE_SUBMITTED_FILES_LIST]
          [--save-manifest-tar SAVE_MANIFEST_TAR] [--files FILES] [--sub-path SUB_PATH] [--workspace-name WORKSPACE_NAME] 
          [--excluded-ecosystems EXCLUDED_ECOSYSTEMS] [--default-branch] [--pending-head] [--generate-license] [--enable-debug] 
          [--enable-json] [--enable-sarif] [--disable-overview] [--exclude-license-details] [--allow-unverified] [--disable-security-issue] 
          [--ignore-commit-files] [--disable-blocking] [--enable-diff] [--scm SCM] [--timeout TIMEOUT] [--include-module-folders] 
          [--reach] [--reach-version REACH_VERSION] [--reach-analysis-timeout REACH_ANALYSIS_TIMEOUT] 
          [--reach-analysis-memory-limit REACH_ANALYSIS_MEMORY_LIMIT] [--reach-ecosystems REACH_ECOSYSTEMS] [--reach-exclude-paths REACH_EXCLUDE_PATHS]
          [--reach-min-severity {low,medium,high,critical}] [--reach-skip-cache] [--reach-disable-analytics] [--reach-output-file REACH_OUTPUT_FILE]
          [--only-facts-file] [--version]
````

If you don't want to provide the Socket API Token every time then you can use the environment variable `SOCKET_SECURITY_API_TOKEN`

### Parameters

#### Authentication
| Parameter   | Required | Default | Description                                                                       |
|:------------|:---------|:--------|:----------------------------------------------------------------------------------|
| --api-token | False    |         | Socket Security API token (can also be set via SOCKET_SECURITY_API_TOKEN env var) |

#### Repository
| Parameter        | Required | Default | Description                                                             |
|:-----------------|:---------|:--------|:------------------------------------------------------------------------|
| --repo           | False    | *auto*  | Repository name in owner/repo format (auto-detected from git remote)   |
| --repo-is-public | False    | False   | If set, flags a new repository creation as public. Defaults to false.   |
| --integration    | False    | api     | Integration type (api, github, gitlab, azure, bitbucket)                |
| --owner          | False    |         | Name of the integration owner, defaults to the socket organization slug |
| --branch         | False    | *auto*  | Branch name (auto-detected from git)                                   |
| --committers     | False    | *auto*  | Committer(s) to filter by (auto-detected from git commit)              |

#### Pull Request and Commit
| Parameter        | Required | Default | Description                                    |
|:-----------------|:---------|:--------|:-----------------------------------------------|
| --pr-number      | False    | "0"     | Pull request number                            |
| --commit-message | False    | *auto*  | Commit message (auto-detected from git)       |
| --commit-sha     | False    | *auto*  | Commit SHA (auto-detected from git)           |

#### Path and File
| Parameter                   | Required | Default               | Description                                                                                                                                                                      |
|:----------------------------|:---------|:----------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --target-path               | False    | ./                    | Target path for analysis                                                                                                                                                         |
| --sbom-file                 | False    |                       | SBOM file path                                                                                                                                                                   |
| --license-file-name         | False    | `license_output.json` | Name of the file to save the license details to if enabled                                                                                                                       |
| --save-submitted-files-list | False    |                       | Save list of submitted file names to JSON file for debugging purposes                                                                                                            |
| --save-manifest-tar         | False    |                       | Save all manifest files to a compressed tar.gz archive with original directory structure                                                                                         |
| --files                     | False    | *auto*                | Files to analyze (JSON array string). Auto-detected from git commit changes when not specified                                                                                   |
| --sub-path                  | False    |                       | Sub-path within target-path for manifest file scanning (can be specified multiple times). All sub-paths are combined into a single workspace scan while preserving git context from target-path. Must be used with --workspace-name |
| --workspace-name            | False    |                       | Workspace name suffix to append to repository name (repo-name-workspace_name). Must be used with --sub-path                                                                     |
| --excluded-ecosystems       | False    | []                    | List of ecosystems to exclude from analysis (JSON array string). You can get supported files from the [Supported Files API](https://docs.socket.dev/reference/getsupportedfiles) |

#### Branch and Scan Configuration
| Parameter                | Required | Default | Description                                                                                           |
|:-------------------------|:---------|:--------|:------------------------------------------------------------------------------------------------------|
| --default-branch         | False    | *auto*  | Make this branch the default branch (auto-detected from git and CI environment when not specified)   |
| --pending-head           | False    | *auto*  | If true, the new scan will be set as the branch's head scan (automatically synced with default-branch) |
| --include-module-folders | False    | False   | If enabled will include manifest files from folders like node_modules                                |

#### Output Configuration
| Parameter                 | Required | Default | Description                                                                       |
|:--------------------------|:---------|:--------|:----------------------------------------------------------------------------------|
| --generate-license        | False    | False   | Generate license information                                                      |
| --enable-debug            | False    | False   | Enable debug logging                                                              |
| --enable-json             | False    | False   | Output in JSON format                                                             |
| --enable-sarif            | False    | False   | Enable SARIF output of results instead of table or JSON format                    |
| --disable-overview        | False    | False   | Disable overview output                                                           |
| --exclude-license-details | False    | False   | Exclude license details from the diff report (boosts performance for large repos) |
| --version                 | False    | False   | Show program's version number and exit                                            |

#### Security Configuration
| Parameter                | Required | Default | Description                   |
|:-------------------------|:---------|:--------|:------------------------------|
| --allow-unverified       | False    | False   | Allow unverified packages     |
| --disable-security-issue | False    | False   | Disable security issue checks |

#### Reachability Analysis
| Parameter                        | Required | Default | Description                                                                                                                |
|:---------------------------------|:---------|:--------|:---------------------------------------------------------------------------------------------------------------------------|
| --reach                          | False    | False   | Enable reachability analysis to identify which vulnerable functions are actually called by your code                       |
| --reach-version                  | False    | latest  | Version of @coana-tech/cli to use for analysis                                                                             |
| --reach-analysis-timeout         | False    | 1200    | Timeout in seconds for the reachability analysis (default: 1200 seconds / 20 minutes)                                      |
| --reach-analysis-memory-limit    | False    | 4096    | Memory limit in MB for the reachability analysis (default: 4096 MB / 4 GB)                                                 |
| --reach-concurrency              | False    |         | Control parallel analysis execution (must be >= 1)                                                                         |
| --reach-additional-params        | False    |         | Pass custom parameters to the coana CLI tool                                                                               |
| --reach-ecosystems               | False    |         | Comma-separated list of ecosystems to analyze (e.g., "npm,pypi"). If not specified, all supported ecosystems are analyzed  |
| --reach-exclude-paths            | False    |         | Comma-separated list of file paths or patterns to exclude from reachability analysis                                       |
| --reach-min-severity             | False    |         | Minimum severity level for reporting reachability results (low, medium, high, critical)                                    |
| --reach-skip-cache               | False    | False   | Skip cache and force fresh reachability analysis                                                                           |
| --reach-disable-analytics        | False    | False   | Disable analytics collection during reachability analysis                                                                  |
| --reach-output-file              | False    | .socket.facts.json | Path where reachability analysis results should be saved                                                        |
| --only-facts-file                | False    | False   | Submit only the .socket.facts.json file to an existing scan (requires --reach and a prior scan)                            |

**Reachability Analysis Requirements:**
- `npm` - Required to install and run @coana-tech/cli
- `npx` - Required to execute @coana-tech/cli
- `uv` - Required for Python environment management

The CLI will automatically install @coana-tech/cli if not present. Use `--reach` to enable reachability analysis during a full scan, or use `--only-facts-file` with `--reach` to submit reachability results to an existing scan.

#### Advanced Configuration
| Parameter                | Required | Default | Description                                                           |
|:-------------------------|:---------|:--------|:----------------------------------------------------------------------|
| --ignore-commit-files    | False    | False   | Ignore commit files                                                   |
| --disable-blocking       | False    | False   | Disable blocking mode                                                 |
| --enable-diff            | False    | False   | Enable diff mode even when using --integration api (forces diff mode without SCM integration) |
| --scm                    | False    | api     | Source control management type                                        |
| --timeout                | False    |         | Timeout in seconds for API requests                                   |

#### Plugins

The Python CLI currently Supports the following plugins:

- Jira
- Slack

##### Jira

| Environment Variable    | Required | Default | Description                        |
|:------------------------|:---------|:--------|:-----------------------------------|
| SOCKET_JIRA_ENABLED     | False    | false   | Enables/Disables the Jira Plugin   |
| SOCKET_JIRA_CONFIG_JSON | True     | None    | Required if the Plugin is enabled. |

Example `SOCKET_JIRA_CONFIG_JSON` value

````json
{"url": "https://REPLACE_ME.atlassian.net", "email": "example@example.com", "api_token": "REPLACE_ME", "project": "REPLACE_ME" }
````

##### Slack

| Environment Variable     | Required | Default | Description                        |
|:-------------------------|:---------|:--------|:-----------------------------------|
| SOCKET_SLACK_CONFIG_JSON | False    | None    | Slack configuration (enables plugin when set). Supports webhook or bot mode. Alternatively, use --slack-webhook CLI flag for simple webhook mode. |
| SOCKET_SLACK_BOT_TOKEN   | False    | None    | Slack Bot User OAuth Token (starts with `xoxb-`). Required when using bot mode. |

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
- `reachability_alerts_only` (boolean, default: false): When `--reach` is enabled, only send blocking alerts (error=true) from diff scans
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
2. **CI environment detection**: Uses CI platform variables (GitHub Actions, GitLab CI)
3. **Git repository analysis**: Compares current branch with repository's default branch
4. **Fallback**: Defaults to `false` if none of the above methods succeed

Both `--default-branch` and `--pending-head` parameters are automatically synchronized to ensure consistent behavior.

## GitLab Token Configuration

The CLI supports GitLab integration with automatic authentication pattern detection for different token types.

### Supported Token Types

GitLab API supports two authentication methods, and the CLI automatically detects which one to use:

1. **Bearer Token Authentication** (`Authorization: Bearer <token>`)
   - GitLab CI Job Tokens (`$CI_JOB_TOKEN`)
   - Personal Access Tokens with `glpat-` prefix
   - OAuth 2.0 tokens (long alphanumeric tokens)

2. **Private Token Authentication** (`PRIVATE-TOKEN: <token>`)
   - Legacy personal access tokens
   - Custom tokens that don't match Bearer patterns

### Token Detection Logic

The CLI automatically determines the authentication method using this logic:

```
if token == $CI_JOB_TOKEN:
    use Bearer authentication
elif token starts with "glpat-":
    use Bearer authentication  
elif token is long (>40 chars) and alphanumeric:
    use Bearer authentication
else:
    use PRIVATE-TOKEN authentication
```

### Automatic Fallback

If the initial authentication method fails with a 401 error, the CLI automatically retries with the alternative method:

- **Bearer → PRIVATE-TOKEN**: If Bearer authentication fails, retry with PRIVATE-TOKEN
- **PRIVATE-TOKEN → Bearer**: If PRIVATE-TOKEN fails, retry with Bearer authentication

This ensures maximum compatibility across different GitLab configurations and token types.

### Environment Variables

| Variable | Description | Example |
|:---------|:------------|:--------|
| `GITLAB_TOKEN` | GitLab API token (required for GitLab integration) | `glpat-xxxxxxxxxxxxxxxxxxxx` |
| `CI_JOB_TOKEN` | GitLab CI job token (automatically used in GitLab CI) | Automatically provided by GitLab CI |

### Usage Examples

**GitLab CI with job token (recommended):**
```yaml
variables:
  GITLAB_TOKEN: $CI_JOB_TOKEN
```

**GitLab CI with personal access token:**
```yaml
variables:
  GITLAB_TOKEN: $GITLAB_PERSONAL_ACCESS_TOKEN  # Set in GitLab project/group variables
```

**Local development:**
```bash
export GITLAB_TOKEN="glpat-your-personal-access-token"
socketcli --integration gitlab --repo owner/repo --pr-number 123
```

### Scan Behavior

The CLI determines scanning behavior intelligently:

- **Manifest files changed**: Performs differential scan with PR/MR comments when supported
- **No manifest files changed**: Creates full repository scan report without waiting for diff results
- **Force API mode**: When no supported manifest files are detected, automatically enables non-blocking mode

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

## Debugging and Troubleshooting

### Saving Submitted Files List

The CLI provides a debugging option to save the list of files that were submitted for scanning:

```bash
socketcli --save-submitted-files-list submitted_files.json
```

This will create a JSON file containing:
- Timestamp of when the scan was performed
- Total number of files submitted
- Total size of all files (in bytes and human-readable format)
- Complete list of file paths that were found and submitted for scanning

Example output file:
```json
{
  "timestamp": "2025-01-22 10:30:45 UTC",
  "total_files": 3,
  "total_size_bytes": 2048,
  "total_size_human": "2.00 KB",
  "files": [
    "./package.json",
    "./requirements.txt",
    "./Pipfile"
  ]
}
```

This feature is useful for:
- **Debugging**: Understanding which files the CLI found and submitted
- **Verification**: Confirming that expected manifest files are being detected
- **Size Analysis**: Understanding the total size of manifest files being uploaded
- **Troubleshooting**: Identifying why certain files might not be included in scans or if size limits are being hit

> **Note**: This option works with both differential scans (when git commits are detected) and full scans (API mode).

### Saving Manifest Files Archive

For backup, sharing, or analysis purposes, you can save all manifest files to a compressed tar.gz archive:

```bash
socketcli --save-manifest-tar manifest_files.tar.gz
```

This will create a compressed archive containing all the manifest files that were found and submitted for scanning, preserving their original directory structure relative to the scanned directory.

Example usage with other options:
```bash
# Save both files list and archive
socketcli --save-submitted-files-list files.json --save-manifest-tar backup.tar.gz

# Use with specific target path
socketcli --target-path ./my-project --save-manifest-tar my-project-manifests.tar.gz
```

The manifest archive feature is useful for:
- **Backup**: Creating portable backups of all dependency manifest files
- **Sharing**: Sending the exact files being analyzed to colleagues or support
- **Analysis**: Examining the dependency files offline or with other tools
- **Debugging**: Verifying file discovery and content issues
- **Compliance**: Maintaining records of scanned dependency files

> **Note**: The tar.gz archive preserves the original directory structure, making it easy to extract and examine the files in their proper context.

### Differential scan skipped on octopus merge

When your repo uses an **octopus merge** (3+ parents), the CLI may not detect all changed files.  
This is expected Git behavior: the default diff only compares the merge result to the first parent.

## Development

This project uses `pyproject.toml` as the primary dependency specification.

### Development Workflows

The following Make targets provide streamlined workflows for common development tasks:

#### Initial Setup (Choose One)

1. Standard Setup (using PyPI packages):
```bash
pyenv local 3.11  # Ensure correct Python version
make first-time-setup
```

2. Local Development Setup (for SDK development):
```bash
pyenv local 3.11  # Ensure correct Python version
SOCKET_SDK_PATH=~/path/to/socketdev make first-time-local-setup
```
The default SDK path is `../socketdev` if not specified.

#### Ongoing Development Tasks

After changing dependencies in pyproject.toml:
```bash
make update-deps
```

After pulling changes:
```bash
make sync-all
```

### Available Make targets:

High-level workflows:
- `make first-time-setup`: Complete setup using PyPI packages
- `make first-time-local-setup`: Complete setup for local SDK development
- `make update-lock`: Update uv.lock file after changing pyproject.toml
- `make sync-all`: Sync dependencies after pulling changes
- `make dev-setup`: Setup for local development (included in first-time-local-setup)

Implementation targets:
- `make local-dev`: Installs dependencies needed for local development
- `make setup`: Creates virtual environment and installs dependencies from uv.lock
- `make sync`: Installs exact versions from uv.lock
- `make clean`: Removes virtual environment and cache files
- `make test`: Runs pytest suite using uv run
- `make lint`: Runs ruff for code formatting and linting using uv run

### Environment Variables

#### Core Configuration
- `SOCKET_SECURITY_API_TOKEN`: Socket Security API token (alternative to --api-token parameter)
  - For backwards compatibility, also accepts: `SOCKET_SECURITY_API_KEY`, `SOCKET_API_KEY`, `SOCKET_API_TOKEN`
- `SOCKET_SDK_PATH`: Path to local socketdev repository (default: ../socketdev)

#### GitLab Integration
- `GITLAB_TOKEN`: GitLab API token for GitLab integration (supports both Bearer and PRIVATE-TOKEN authentication)
- `CI_JOB_TOKEN`: GitLab CI job token (automatically provided in GitLab CI environments)

### Manual Development Environment Setup

For manual setup without using the Make targets, follow these steps:

1. **Create a virtual environment:**
```bash
python -m venv .venv
```

2. **Activate the virtual environment:**
```bash
source .venv/bin/activate
```

3. **Sync dependencies with uv:**
```bash
uv sync
```

4. **Install pre-commit:**
```bash
uv add --dev pre-commit
```

5. **Register the pre-commit hook:**
```bash
pre-commit install
```

> **Note**: This manual setup is an alternative to the streamlined Make targets described above. For most development workflows, using `make first-time-setup` or `make first-time-local-setup` is recommended.

