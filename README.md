# Socket Security CLI

The Socket Security CLI was created to enable integrations with other tools like Github Actions, Gitlab, BitBucket, local use cases and more. The tool will get the head scan for the provided repo from Socket, create a new one, and then report any new alerts detected. If there are new alerts against the Socket security policy it'll exit with a non-Zero exit code.

## Usage

```` shell
socketcli [-h] [--api_token API_TOKEN] [--repo REPO] [--branch BRANCH] [--committer COMMITTER] [--pr_number PR_NUMBER] [--commit_message COMMIT_MESSAGE] [--default_branch DEFAULT_BRANCH]
                 [--target_path TARGET_PATH] [--mode {diff,new,license}] [--scm {api,github}] [--generate-license GENERATE_LICENSE]
````

If you don't want to provide the Socket API Token every time then you can use the environment variable `SOCKET_SECURITY_API_KEY`


| Parameter          | Alternate Name | Required | Default | Description                                                                                                                                                |
|:-------------------|:---------------|:---------|:--------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| -h                 | --help         | False    |         | Show the CLI help message                                                                                                                                  |
| --api_token        |                | False    |         | Provides the Socket API Token                                                                                                                              |
| --repo             |                | True     |         | The string name in a git approved name for repositories.                                                                                                   |
| --branch           |                | False    |         | The string name in a git approved name for branches.                                                                                                       |
| --committer        |                | False    |         | The string name of the person doing the commit or running the CLI. Can be specified multiple times to have more than one committer                         |
| --pr_number        |                | False    | 0       | The integer for the PR or MR number                                                                                                                        |
| --commit_message   |                | False    |         | The string for a commit message if there is one                                                                                                            |
| --default_branch   |                | False    | False   | If the flag is specified this will signal that this is the default branch. This needs to be enabled for a report to update Org Alerts and Org Dependencies |
| --target_path      |                | False    | ./      | This is the path to where the manifest files are location. The tool will recursively search for all supported manifest files                               |
| --scm              |                | False    | api     | This is the mode that the tool is to run in. For local runs `api` would be the mode. Other options are `gitlab` and `github`                               |
| --generate-license |                | False    | False   | If this flag is specified it will generate a json file with the license per package and license text in the current working directory                      |
| --version          | -v             | False    |         | Prints the version and exits                                                                                                                               |
| --enable-debug     |                | False    | False   | Enables debug messaging for the CLI                                                                                                                        |
