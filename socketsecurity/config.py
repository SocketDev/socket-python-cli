import argparse
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import List, Optional
from socketsecurity import __version__
from socketdev import INTEGRATION_TYPES, IntegrationType
import json


def get_plugin_config_from_env(prefix: str) -> dict:
    config_str = os.getenv(f"{prefix}_CONFIG_JSON", "{}")
    try:
        return json.loads(config_str)
    except json.JSONDecodeError:
        return {}

@dataclass
class PluginConfig:
    enabled: bool = False
    levels: List[str] = None
    config: Optional[dict] = None


@dataclass
class CliConfig:
    api_token: str
    repo: Optional[str]
    branch: str = ""
    committers: Optional[List[str]] = None
    pr_number: str = "0"
    commit_message: Optional[str] = None
    default_branch: bool = False
    target_path: str = "./"
    scm: str = "api"
    sbom_file: Optional[str] = None
    commit_sha: str = ""
    generate_license: bool = False
    enable_debug: bool = False
    allow_unverified: bool = False
    enable_json: bool = False
    enable_sarif: bool = False
    disable_overview: bool = False
    disable_security_issue: bool = False
    files: str = None
    ignore_commit_files: bool = False
    disable_blocking: bool = False
    integration_type: IntegrationType = "api"
    integration_org_slug: Optional[str] = None
    pending_head: bool = False
    timeout: Optional[int] = 1200
    exclude_license_details: bool = False
    include_module_folders: bool = False
    repo_is_public: bool = False
    excluded_ecosystems: list[str] = field(default_factory=lambda: [])
    version: str = __version__
    jira_plugin: PluginConfig = field(default_factory=PluginConfig)
    slack_plugin: PluginConfig = field(default_factory=PluginConfig)
    license_file_name: str = "license_output.json"
    save_submitted_files_list: Optional[str] = None
    save_manifest_tar: Optional[str] = None

    @classmethod
    def from_args(cls, args_list: Optional[List[str]] = None) -> 'CliConfig':
        parser = create_argument_parser()
        args = parser.parse_args(args_list)

        # Get API token from env or args
        api_token = os.getenv("SOCKET_SECURITY_API_KEY") or args.api_token

        # Strip quotes from commit message if present
        commit_message = args.commit_message
        if commit_message and commit_message.startswith('"') and commit_message.endswith('"'):
            commit_message = commit_message[1:-1]

        config_args = {
            'api_token': api_token,
            'repo': args.repo,
            'branch': args.branch,
            'committers': args.committers,
            'pr_number': args.pr_number,
            'commit_message': commit_message,
            'default_branch': args.default_branch,
            'target_path': os.path.expanduser(args.target_path),
            'scm': args.scm,
            'sbom_file': args.sbom_file,
            'commit_sha': args.commit_sha,
            'generate_license': args.generate_license,
            'enable_debug': args.enable_debug,
            'allow_unverified': args.allow_unverified,
            'enable_json': args.enable_json,
            'enable_sarif': args.enable_sarif,
            'disable_overview': args.disable_overview,
            'disable_security_issue': args.disable_security_issue,
            'files': args.files,
            'ignore_commit_files': args.ignore_commit_files,
            'disable_blocking': args.disable_blocking,
            'integration_type': args.integration,
            'pending_head': args.pending_head,
            'timeout': args.timeout,
            'exclude_license_details': args.exclude_license_details,
            'include_module_folders': args.include_module_folders,
            'repo_is_public': args.repo_is_public,
            "excluded_ecosystems": args.excluded_ecosystems,
            'license_file_name': args.license_file_name,
            'save_submitted_files_list': args.save_submitted_files_list,
            'save_manifest_tar': args.save_manifest_tar,
            'version': __version__
        }
        try:
            config_args["excluded_ecosystems"] = json.loads(config_args["excluded_ecosystems"].replace("'", '"'))
        except json.JSONDecodeError:
            logging.error(f"Unable to parse excluded_ecosystems: {config_args['excluded_ecosystems']}")
            exit(1)
        config_args.update({
            "jira_plugin": PluginConfig(
                enabled=os.getenv("SOCKET_JIRA_ENABLED", "false").lower() == "true",
                levels=os.getenv("SOCKET_JIRA_LEVELS", "block,warn").split(","),
                config=get_plugin_config_from_env("SOCKET_JIRA")
            ),
            "slack_plugin": PluginConfig(
                enabled=os.getenv("SOCKET_SLACK_ENABLED", "false").lower() == "true",
                levels=os.getenv("SOCKET_SLACK_LEVELS", "block,warn").split(","),
                config=get_plugin_config_from_env("SOCKET_SLACK")
            )
        })

        if args.owner:
            config_args['integration_org_slug'] = args.owner

        return cls(**config_args)

    def to_dict(self) -> dict:
        return asdict(self)

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socketcli",
        description="The Socket Security CLI will get the head scan for the provided repo from Socket, create a new one, and then report any alerts introduced by the changes. Any new alerts will cause the CLI to exit with a non-Zero exit code (1 for error alerts, 5 for warnings)."
    )

    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument(
        "--api-token",
        dest="api_token",
        metavar="<token>",
        help="Socket Security API token (can also be set via SOCKET_SECURITY_API_KEY env var)",
        required=False
    )
    auth_group.add_argument(
        "--api_token",
        dest="api_token",
        help=argparse.SUPPRESS
    )

    # Repository info
    repo_group = parser.add_argument_group('Repository')
    repo_group.add_argument(
        "--repo",
        metavar="<owner/repo>",
        help="Repository name in owner/repo format",
        required=False
    )
    repo_group.add_argument(
        "--repo-is-public",
        dest="repo_is_public",
        action="store_true",
        help="If set it will flag a new repository creation as public. Defaults to false."
    )
    repo_group.add_argument(
        "--branch",
        metavar="<name>",
        help="Branch name",
        default=""
    )

    integration_group = parser.add_argument_group('Integration')
    integration_group.add_argument(
        "--integration",
        choices=INTEGRATION_TYPES,
        metavar="<type>",
        help="Integration type of api, github, gitlab, azure, or bitbucket. Defaults to api",
        default="api"
    )
    integration_group.add_argument(
        "--owner",
        metavar="<name>",
        help="Name of the integration owner, defaults to the socket organization slug",
        required=False
    )

    # Pull Request and Commit info
    pr_group = parser.add_argument_group('Pull Request and Commit')
    pr_group.add_argument(
        "--pr-number",
        dest="pr_number",
        metavar="<number>",
        help="Pull request number",
        default="0"
    )
    pr_group.add_argument(
        "--pr_number",
        dest="pr_number",
        help=argparse.SUPPRESS
    )
    pr_group.add_argument(
        "--commit-message",
        dest="commit_message",
        metavar="<message>",
        help="Commit message"
    )
    pr_group.add_argument(
        "--commit_message",
        dest="commit_message",
        help=argparse.SUPPRESS
    )
    pr_group.add_argument(
        "--commit-sha",
        dest="commit_sha",
        metavar="<sha>",
        default="",
        help="Commit SHA"
    )
    pr_group.add_argument(
        "--commit_sha",
        dest="commit_sha",
        help=argparse.SUPPRESS
    )
    pr_group.add_argument(
        "--committers",
        metavar="<name>",
        help="Committer for the commit (comma separated)",
        nargs="*"
    )

    # Path and File options
    path_group = parser.add_argument_group('Path and File')
    path_group.add_argument(
        "--target-path",
        dest="target_path",
        metavar="<path>",
        default="./",
        help="Target path for analysis"
    )
    path_group.add_argument(
        "--target_path",
        dest="target_path",
        help=argparse.SUPPRESS
    )
    path_group.add_argument(
        "--sbom-file",
        dest="sbom_file",
        metavar="<path>",
        help="SBOM file path"
    )
    path_group.add_argument(
        "--sbom_file",
        dest="sbom_file",
        help=argparse.SUPPRESS
    )
    path_group.add_argument(
        "--license-file-name",
        dest="license_file_name",
        default="license_output.json",
        metavar="<string>",
        help="SBOM file path"
    )
    path_group.add_argument(
        "--save-submitted-files-list",
        dest="save_submitted_files_list",
        metavar="<path>",
        help="Save list of submitted file names to JSON file for debugging purposes"
    )
    path_group.add_argument(
        "--save-manifest-tar",
        dest="save_manifest_tar",
        metavar="<path>",
        help="Save all manifest files to a compressed tar.gz archive with original directory structure"
    )
    path_group.add_argument(
        "--files",
        metavar="<json>",
        default="[]",
        help="Files to analyze (JSON array string)"
    )

    path_group.add_argument(
        "--excluded-ecosystems",
        default="[]",
        dest="excluded_ecosystems",
        help="List of ecosystems to exclude from analysis (JSON array string)"
    )

    # Branch and Scan Configuration
    config_group = parser.add_argument_group('Branch and Scan Configuration')
    config_group.add_argument(
        "--default-branch",
        dest="default_branch",
        action="store_true",
        help="Make this branch the default branch"
    )
    config_group.add_argument(
        "--default_branch",
        dest="default_branch",
        action="store_true",
        help=argparse.SUPPRESS
    )
    config_group.add_argument(
        "--pending-head",
        dest="pending_head",
        action="store_true",
        help="If true, the new scan will be set as the branch's head scan"
    )
    config_group.add_argument(
        "--pending_head",
        dest="pending_head",
        action="store_true",
        help=argparse.SUPPRESS
    )
    # Output Configuration
    output_group = parser.add_argument_group('Output Configuration')
    output_group.add_argument(
        "--generate-license",
        dest="generate_license",
        action="store_true",
        help="Generate license information"
    )
    output_group.add_argument(
        "--generate_license",
        dest="generate_license",
        action="store_true",
        help=argparse.SUPPRESS
    )
    output_group.add_argument(
        "--enable-debug",
        dest="enable_debug",
        action="store_true",
        help="Enable debug logging"
    )
    output_group.add_argument(
        "--enable_debug",
        dest="enable_debug",
        action="store_true",
        help=argparse.SUPPRESS
    )
    output_group.add_argument(
        "--enable-json",
        dest="enable_json",
        action="store_true",
        help="Output in JSON format"
    )
    output_group.add_argument(
        "--enable-sarif",
        dest="enable_sarif",
        action="store_true",
        help="Enable SARIF output of results instead of table or JSON format"
    )
    output_group.add_argument(
        "--disable-overview",
        dest="disable_overview",
        action="store_true",
        help="Disable overview output"
    )
    output_group.add_argument(
        "--disable_overview",
        dest="disable_overview",
        action="store_true",
        help=argparse.SUPPRESS
    )
    output_group.add_argument(
        "--exclude-license-details",
        dest="exclude_license_details",
        action="store_true",
        help="Exclude license details from the diff report (boosts performance for large repos)"
    )

    # Security Configuration
    security_group = parser.add_argument_group('Security Configuration')
    security_group.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow unverified packages"
    )
    security_group.add_argument(
        "--disable-security-issue",
        dest="disable_security_issue",
        action="store_true",
        help="Disable security issue checks"
    )
    security_group.add_argument(
        "--disable_security_issue",
        dest="disable_security_issue",
        action="store_true",
        help=argparse.SUPPRESS
    )

    # Advanced Configuration
    advanced_group = parser.add_argument_group('Advanced Configuration')
    advanced_group.add_argument(
        "--ignore-commit-files",
        dest="ignore_commit_files",
        action="store_true",
        help="Ignore commit files"
    )
    advanced_group.add_argument(
        "--ignore_commit_files",
        dest="ignore_commit_files",
        action="store_true",
        help=argparse.SUPPRESS
    )
    advanced_group.add_argument(
        "--disable-blocking",
        dest="disable_blocking",
        action="store_true",
        help="Disable blocking mode"
    )
    advanced_group.add_argument(
        "--disable_blocking",
        dest="disable_blocking",
        action="store_true",
        help=argparse.SUPPRESS
    )
    advanced_group.add_argument(
        "--scm",
        metavar="<type>",
        default="api",
        help="Source control management type"
    )
    advanced_group.add_argument(
        "--timeout",
        type=int,
        metavar="<seconds>",
        help="Timeout in seconds for API requests",
        required=False
    )
    config_group.add_argument(
        "--include-module-folders",
        dest="include_module_folders",
        action="store_true",
        default=False,
        help="Enabling including module folders like node_modules"
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    return parser