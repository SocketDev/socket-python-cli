# Socket Security CLI

The Socket Security CLI was created to enable integrations with other tools like Github Actions, Gitlab, BitBucket, local use cases and more. The tool will get the head scan for the provided repo from Socket, create a new one, and then report any new alerts detected. If there are new alerts against the Socket security policy it'll exit with a non-Zero exit code.

## Usage

```` shell
socketcli [-h] [--api-token API_TOKEN] [--repo REPO] [--integration {api,github,gitlab}] [--owner OWNER] [--branch BRANCH] 
          [--committers [COMMITTERS ...]] [--pr-number PR_NUMBER] [--commit-message COMMIT_MESSAGE] [--commit-sha COMMIT_SHA] 
          [--target-path TARGET_PATH] [--sbom-file SBOM_FILE] [--files FILES] [--default-branch] [--pending-head] 
          [--generate-license] [--enable-debug] [--enable-json] [--enable-sarif] [--disable-overview] [--disable-security-issue] 
          [--allow-unverified] [--ignore-commit-files] [--disable-blocking] [--scm SCM] [--timeout TIMEOUT]
          [--exclude-license-details]
````

If you don't want to provide the Socket API Token every time then you can use the environment variable `SOCKET_SECURITY_API_KEY`

### Parameters

#### Authentication
| Parameter     | Required | Default | Description                                                                           |
|:-------------|:---------|:--------|:--------------------------------------------------------------------------------------|
| --api-token  | False    |         | Socket Security API token (can also be set via SOCKET_SECURITY_API_KEY env var)       |

#### Repository
| Parameter    | Required | Default | Description                                                              |
|:-------------|:---------|:--------|:-------------------------------------------------------------------------|
| --repo       | False    |         | Repository name in owner/repo format                                     |
| --integration| False    | api     | Integration type (api, github, gitlab)                                   |
| --owner      | False    |         | Name of the integration owner, defaults to the socket organization slug  |
| --branch     | False    | ""      | Branch name                                                             |
| --committers | False    |         | Committer(s) to filter by                                               |

#### Pull Request and Commit
| Parameter       | Required | Default | Description        |
|:----------------|:---------|:--------|:-------------------|
| --pr-number     | False    | "0"     | Pull request number|
| --commit-message| False    |         | Commit message     |
| --commit-sha    | False    | ""      | Commit SHA         |

#### Path and File
| Parameter    | Required | Default | Description                                |
|:-------------|:---------|:--------|:-------------------------------------------|
| --target-path| False    | ./      | Target path for analysis                   |
| --sbom-file  | False    |         | SBOM file path                            |
| --files      | False    | []      | Files to analyze (JSON array string)       |

#### Branch and Scan Configuration
| Parameter      | Required | Default | Description                                               |
|:---------------|:---------|:--------|:----------------------------------------------------------|
| --default-branch| False    | False   | Make this branch the default branch                       |
| --pending-head | False    | False   | If true, the new scan will be set as the branch's head scan|

#### Output Configuration
| Parameter              | Required | Default | Description                                                    |
|:----------------------|:---------|:--------|:---------------------------------------------------------------|
| --generate-license    | False    | False   | Generate license information                                   |
| --enable-debug       | False    | False   | Enable debug logging                                          |
| --enable-json        | False    | False   | Output in JSON format                                         |
| --enable-sarif       | False    | False   | Enable SARIF output of results instead of table or JSON format|
| --disable-overview   | False    | False   | Disable overview output                                       |
| --exclude-license-details | False    | False   | Exclude license details from the diff report (boosts performance for large repos) |

#### Security Configuration
| Parameter               | Required | Default | Description                    |
|:-----------------------|:---------|:--------|:-------------------------------|
| --allow-unverified     | False    | False   | Allow unverified packages     |
| --disable-security-issue| False    | False   | Disable security issue checks |

#### Advanced Configuration
| Parameter           | Required | Default | Description                                    |
|:-------------------|:---------|:--------|:-----------------------------------------------|
| --ignore-commit-files| False    | False   | Ignore commit files                           |
| --disable-blocking  | False    | False   | Disable blocking mode                         |
| --scm              | False    | api     | Source control management type                |
| --timeout          | False    |         | Timeout in seconds for API requests           |

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
SOCKET_SDK_PATH=~/path/to/socket-sdk-python make first-time-local-setup
```
The default SDK path is `../socket-sdk-python` if not specified.

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
- `make update-deps`: Update requirements.txt files and sync dependencies
- `make sync-all`: Sync dependencies after pulling changes
- `make dev-setup`: Setup for local development (included in first-time-local-setup)

Implementation targets:
- `make init-tools`: Creates virtual environment and installs pip-tools
- `make local-dev`: Installs dependencies needed for local development
- `make compile-deps`: Generates requirements.txt files with locked versions
- `make setup`: Creates virtual environment and installs dependencies
- `make sync-deps`: Installs exact versions from requirements.txt
- `make clean`: Removes virtual environment and cache files
- `make test`: Runs pytest suite
- `make lint`: Runs ruff for code formatting and linting

### Environment Variables

- `SOCKET_SDK_PATH`: Path to local socket-sdk-python repository (default: ../socket-sdk-python)

### Running tests:

#### Run all tests:
```