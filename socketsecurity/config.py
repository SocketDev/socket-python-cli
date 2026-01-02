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
    enable_diff: bool = False
    timeout: Optional[int] = 1200
    exclude_license_details: bool = False
    include_module_folders: bool = False
    repo_is_public: bool = False
    excluded_ecosystems: list[str] = field(default_factory=lambda: [])
    version: str = __version__
    jira_plugin: PluginConfig = field(default_factory=PluginConfig)
    slack_plugin: PluginConfig = field(default_factory=PluginConfig)
    slack_webhook: Optional[str] = None
    license_file_name: str = "license_output.json"
    save_submitted_files_list: Optional[str] = None
    save_manifest_tar: Optional[str] = None
    sub_paths: List[str] = field(default_factory=list)
    workspace_name: Optional[str] = None
    # Reachability Flags
    reach: bool = False
    reach_version: Optional[str] = None
    reach_analysis_memory_limit: Optional[int] = None
    reach_analysis_timeout: Optional[int] = None
    reach_disable_analytics: bool = False
    reach_disable_analysis_splitting: bool = False
    reach_ecosystems: Optional[List[str]] = None
    reach_exclude_paths: Optional[List[str]] = None
    reach_skip_cache: bool = False
    reach_min_severity: Optional[str] = None
    reach_output_file: Optional[str] = None
    reach_concurrency: Optional[int] = None
    reach_additional_params: Optional[List[str]] = None
    only_facts_file: bool = False
    reach_use_only_pregenerated_sboms: bool = False
    max_purl_batch_size: int = 5000
    
    @classmethod
    def from_args(cls, args_list: Optional[List[str]] = None) -> 'CliConfig':
        parser = create_argument_parser()
        args = parser.parse_args(args_list)

        # Get API token from env or args (check multiple env var names)
        api_token = (
            os.getenv("SOCKET_SECURITY_API_KEY") or
            os.getenv("SOCKET_SECURITY_API_TOKEN") or
            os.getenv("SOCKET_API_KEY") or
            os.getenv("SOCKET_API_TOKEN") or
            args.api_token
        )

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
            'enable_diff': args.enable_diff,
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
            'sub_paths': args.sub_paths or [],
            'workspace_name': args.workspace_name,
            'slack_webhook': args.slack_webhook,
            'reach': args.reach,
            'reach_version': args.reach_version,
            'reach_analysis_timeout': args.reach_analysis_timeout,
            'reach_analysis_memory_limit': args.reach_analysis_memory_limit,
            'reach_disable_analytics': args.reach_disable_analytics,
            'reach_disable_analysis_splitting': args.reach_disable_analysis_splitting,
            'reach_ecosystems': args.reach_ecosystems.split(',') if args.reach_ecosystems else None,
            'reach_exclude_paths': args.reach_exclude_paths.split(',') if args.reach_exclude_paths else None,
            'reach_skip_cache': args.reach_skip_cache,
            'reach_min_severity': args.reach_min_severity,
            'reach_output_file': args.reach_output_file,
            'reach_concurrency': args.reach_concurrency,
            'reach_additional_params': args.reach_additional_params,
            'only_facts_file': args.only_facts_file,
            'reach_use_only_pregenerated_sboms': args.reach_use_only_pregenerated_sboms,
            'max_purl_batch_size': args.max_purl_batch_size,
            'version': __version__
        }
        try:
            config_args["excluded_ecosystems"] = json.loads(config_args["excluded_ecosystems"].replace("'", '"'))
        except json.JSONDecodeError:
            logging.error(f"Unable to parse excluded_ecosystems: {config_args['excluded_ecosystems']}")
            exit(1)
        # Build Slack plugin config, merging CLI arg with env config
        slack_config = get_plugin_config_from_env("SOCKET_SLACK")
        if args.slack_webhook:
            slack_config["url"] = args.slack_webhook
            
        config_args.update({
            "jira_plugin": PluginConfig(
                enabled=os.getenv("SOCKET_JIRA_ENABLED", "false").lower() == "true",
                levels=os.getenv("SOCKET_JIRA_LEVELS", "block,warn").split(","),
                config=get_plugin_config_from_env("SOCKET_JIRA")
            ),
            "slack_plugin": PluginConfig(
                enabled=bool(slack_config) or bool(args.slack_webhook),
                levels=os.getenv("SOCKET_SLACK_LEVELS", "block,warn").split(","),
                config=slack_config
            )
        })

        if args.owner:
            config_args['integration_org_slug'] = args.owner

        # Validate that sub_paths and workspace_name are used together
        if args.sub_paths and not args.workspace_name:
            logging.error("--sub-path requires --workspace-name to be specified")
            exit(1)
        if args.workspace_name and not args.sub_paths:
            logging.error("--workspace-name requires --sub-path to be specified")
            exit(1)

        # Validate that only_facts_file requires reach
        if args.only_facts_file and not args.reach:
            logging.error("--only-facts-file requires --reach to be specified")
            exit(1)

        # Validate that reach_use_only_pregenerated_sboms requires reach
        if args.reach_use_only_pregenerated_sboms and not args.reach:
            logging.error("--reach-use-only-pregenerated-sboms requires --reach to be specified")
            exit(1)

        # Validate reach_concurrency is >= 1 if provided
        if args.reach_concurrency is not None and args.reach_concurrency < 1:
            logging.error("--reach-concurrency must be >= 1")
            exit(1)

        # Validate max_purl_batch_size is within allowed range
        if args.max_purl_batch_size < 1 or args.max_purl_batch_size > 9999:
            logging.error("--max-purl-batch-size must be between 1 and 9999")
            exit(1)

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
        help="Socket Security API token (can also be set via SOCKET_SECURITY_API_TOKEN env var)",
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
        "--sub-path",
        dest="sub_paths",
        metavar="<path>",
        action="append",
        help="Sub-path within target-path for manifest file scanning (can be specified multiple times). All sub-paths will be combined into a single workspace scan while preserving git context from target-path"
    )
    path_group.add_argument(
        "--workspace-name",
        dest="workspace_name", 
        metavar="<name>",
        help="Workspace name suffix to append to repository name (repo-name-workspace_name)"
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
    output_group.add_argument(
        "--max-purl-batch-size",
        dest="max_purl_batch_size",
        type=int,
        default=5000,
        help="Maximum batch size for PURL endpoint calls when generating license info (default: 5000, min: 1, max: 9999)"
    )

    output_group.add_argument(
        "--disable-security-issue",
        dest="disable_security_issue",
        action="store_true",
        help="Disable security issue checks"
    )
    output_group.add_argument(
        "--disable_security_issue",
        dest="disable_security_issue",
        action="store_true",
        help=argparse.SUPPRESS
    )

    # Plugin Configuration
    plugin_group = parser.add_argument_group('Plugin Configuration')
    plugin_group.add_argument(
        "--slack-webhook",
        dest="slack_webhook",
        metavar="<url>",
        help="Slack webhook URL for notifications (automatically enables Slack plugin)"
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
        "--enable-diff",
        dest="enable_diff",
        action="store_true",
        help="Enable diff mode even when using --integration api (forces diff mode without SCM integration)"
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
    advanced_group.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Disable SSL certificate verification for API requests"
    )
    config_group.add_argument(
        "--include-module-folders",
        dest="include_module_folders",
        action="store_true",
        default=False,
        help="Enabling including module folders like node_modules"
    )

    # Reachability Configuration
    reachability_group = parser.add_argument_group('Reachability Analysis')
    reachability_group.add_argument(
        "--reach",
        dest="reach",
        action="store_true",
        help="Enable reachability analysis"
    )
    reachability_group.add_argument(
        "--reach-version",
        dest="reach_version",
        metavar="<version>",
        help="Specific version of @coana-tech/cli to use (e.g., '1.2.3')"
    )
    reachability_group.add_argument(
        "--reach-timeout",
        dest="reach_analysis_timeout",
        type=int,
        metavar="<seconds>",
        help="Timeout for reachability analysis in seconds"
    )
    reachability_group.add_argument(
        "--reach-memory-limit",
        dest="reach_analysis_memory_limit",
        type=int,
        metavar="<mb>",
        help="Memory limit for reachability analysis in MB"
    )
    reachability_group.add_argument(
        "--reach-ecosystems",
        dest="reach_ecosystems",
        metavar="<list>",
        help="Ecosystems to analyze for reachability (comma-separated, e.g., 'npm,pypi')"
    )
    reachability_group.add_argument(
        "--reach-exclude-paths",
        dest="reach_exclude_paths",
        metavar="<list>",
        help="Paths to exclude from reachability analysis (comma-separated)"
    )
    reachability_group.add_argument(
        "--reach-min-severity",
        dest="reach_min_severity",
        metavar="<level>",
        help="Minimum severity level for reachability analysis (info, low, moderate, high, critical)"
    )
    reachability_group.add_argument(
        "--reach-skip-cache",
        dest="reach_skip_cache",
        action="store_true",
        help="Skip cache usage for reachability analysis"
    )
    reachability_group.add_argument(
        "--reach-disable-analytics",
        dest="reach_disable_analytics",
        action="store_true",
        help="Disable analytics sharing for reachability analysis"
    )
    reachability_group.add_argument(
        "--reach-disable-analysis-splitting",
        dest="reach_disable_analysis_splitting",
        action="store_true",
        help="Disable analysis splitting/bucketing for reachability analysis"
    )
    reachability_group.add_argument(
        "--reach-output-file",
        dest="reach_output_file",
        metavar="<path>",
        default=".socket.facts.json",
        help="Output file path for reachability analysis results (default: .socket.facts.json)"
    )
    reachability_group.add_argument(
        "--reach-concurrency",
        dest="reach_concurrency",
        type=int,
        metavar="<number>",
        help="Concurrency level for reachability analysis (must be >= 1)"
    )
    reachability_group.add_argument(
        "--reach-additional-params",
        dest="reach_additional_params",
        nargs='+',
        metavar="<param>",
        help="Additional parameters to pass to the coana CLI (e.g., --reach-additional-params --other-param value --another-param value2)"
    )
    reachability_group.add_argument(
        "--only-facts-file",
        dest="only_facts_file",
        action="store_true",
        help="Submit only the .socket.facts.json file when creating full scan (requires --reach)"
    )
    reachability_group.add_argument(
        "--reach-use-only-pregenerated-sboms",
        dest="reach_use_only_pregenerated_sboms",
        action="store_true",
        help="When using this option, the scan is created based only on pre-generated CDX and SPDX files in your project. (requires --reach)"
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    return parser