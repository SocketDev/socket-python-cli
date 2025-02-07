# Socket Security CLI

The Socket Security CLI was created to enable integrations with other tools like Github Actions, Gitlab, BitBucket, local use cases and more. The tool will get the head scan for the provided repo from Socket, create a new one, and then report any new alerts detected. If there are new alerts against the Socket security policy it'll exit with a non-Zero exit code.



## Usage

```` shell
socketcli [-h] [--api-token API_TOKEN] [--repo REPO] [--branch BRANCH] [--committer COMMITTER] [--pr-number PR_NUMBER]
                 [--commit-message COMMIT_MESSAGE] [--default-branch] [--target-path TARGET_PATH] [--scm {api,github,gitlab}] [--sbom-file SBOM_FILE]
                 [--commit-sha COMMIT_SHA] [--generate-license GENERATE_LICENSE] [-v] [--enable-debug] [--enable-json] [--enable-sarif] [--disable-overview]
                 [--disable-security-issue] [--files FILES] [--ignore-commit-files] [--timeout]
````

If you don't want to provide the Socket API Token every time then you can use the environment variable `SOCKET_SECURITY_API_KEY`


| Parameter                | Alternate Name | Required | Default | Description                                                                                                                                                                                                                   |
|:-------------------------|:---------------|:---------|:--------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -h                       | --help         | False    |         | Show the CLI help message                                                                                                                                                                                                     |
| --api-token              |                | False    |         | Provides the Socket API Token                                                                                                                                                                                                 |
| --repo                   |                | True     |         | The string name in a git approved name for repositories.                                                                                                                                                                      |
| --branch                 |                | False    |         | The string name in a git approved name for branches.                                                                                                                                                                          |
| --committer              |                | False    |         | The string name of the person doing the commit or running the CLI. Can be specified multiple times to have more than one committer                                                                                            |
| --pr-number              |                | False    | 0       | The integer for the PR or MR number                                                                                                                                                                                           |
| --commit-message         |                | False    |         | The string for a commit message if there is one                                                                                                                                                                               |
| --default-branch         |                | False    | False   | If the flag is specified this will signal that this is the default branch. This needs to be enabled for a report to update Org Alerts and Org Dependencies                                                                    |
| --target-path            |                | False    | ./      | This is the path to where the manifest files are location. The tool will recursively search for all supported manifest files                                                                                                  |
| --scm                    |                | False    | api     | This is the mode that the tool is to run in. For local runs `api` would be the mode. Other options are `gitlab` and `github`                                                                                                  |
| --generate-license       |                | False    | False   | If this flag is specified it will generate a json file with the license per package and license text in the current working directory                                                                                         |
| --version                | -v             | False    |         | Prints the version and exits                                                                                                                                                                                                  |
| --enable-debug           |                | False    | False   | Enables debug messaging for the CLI                                                                                                                                                                                           |
| --sbom-file              |                | False    | False   | Creates a JSON file with all dependencies and alerts                                                                                                                                                                          |
| --commit-sha             |                | False    |         | The commit hash for the commit                                                                                                                                                                                                |
| --generate-license       |                | False    | False   | If enabled with `--sbom-file` will include license details                                                                                                                                                                    |
| --enable-json            |                | False    | False   | If enabled will change the console output format to JSON                                                                                                                                                                      |
| --enable-sarif           |                | False    | False   | If enabled will change the console output format to SARIF                                                                                                                                                                     |                  
| --disable-overview       |                | False    | False   | If enabled will disable Dependency Overview comments                                                                                                                                                                          |
| --disable-security-issue |                | False    | False   | If enabled will disable Security Issue Comments                                                                                                                                                                               |
| --files                  |                | False    |         | If provided in the format of `["file1", "file2"]` will be used to determine if there have been supported file changes. This is used if it isn't a git repo and you would like to only run if it supported files have changed. |
| --ignore-commit-files    |                | False    | False   | If enabled then the CLI will ignore what files are changed in the commit and look for all manifest files                                                                                                                      |
| --disable-blocking       |                | False    | False   | Disables failing checks and will only exit with an exit code of 0                                                                                                                                                             |

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