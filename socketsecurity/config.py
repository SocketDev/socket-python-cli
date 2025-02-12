import argparse
import os
from dataclasses import asdict, dataclass
from typing import List, Optional

from socketdev import INTEGRATION_TYPES, IntegrationType


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
    disable_overview: bool = False
    disable_security_issue: bool = False
    files: str = "[]"
    ignore_commit_files: bool = False
    disable_blocking: bool = False
    integration_type: IntegrationType = "api"
    integration_org_slug: Optional[str] = None
    pending_head: bool = False
    timeout: Optional[int] = None
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
            'target_path': args.target_path,
            'scm': args.scm,
            'sbom_file': args.sbom_file,
            'commit_sha': args.commit_sha,
            'generate_license': args.generate_license,
            'enable_debug': args.enable_debug,
            'allow_unverified': args.allow_unverified,
            'enable_json': args.enable_json,
            'disable_overview': args.disable_overview,
            'disable_security_issue': args.disable_security_issue,
            'files': args.files,
            'ignore_commit_files': args.ignore_commit_files,
            'disable_blocking': args.disable_blocking,
            'integration_type': args.integration,
            'pending_head': args.pending_head,
            'timeout': args.timeout,
        }

        if args.owner:
            config_args['integration_org_slug'] = args.owner

        return cls(**config_args)

    def to_dict(self) -> dict:
        return asdict(self)

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socketcli",
        description="Socket Security CLI"
    )

    parser.add_argument(
        "--api-token",
        help="Socket Security API token (can also be set via SOCKET_SECURITY_API_KEY env var)",
        required=False
    )

    parser.add_argument(
        "--repo",
        help="Repository name in owner/repo format",
        required=False
    )

    parser.add_argument(
        "--integration",
        choices=INTEGRATION_TYPES,
        help="Integration type",
        default="api"
    )

    parser.add_argument(
        "--owner",
        help="Name of the integration owner, defaults to the socket organization slug",
        required=False
    )

    parser.add_argument(
        "--branch",
        help="Branch name",
        default=""
    )

    parser.add_argument(
        "--committers",
        help="Committer(s) to filter by",
        nargs="*"
    )

    parser.add_argument(
        "--pr-number",
        help="Pull request number",
        default="0"
    )

    parser.add_argument(
        "--commit-message",
        help="Commit message"
    )

    # Boolean flags
    parser.add_argument(
        "--default-branch",
        action="store_true",
        help="Make this branch the default branch"
    )

    parser.add_argument(
        "--pending-head",
        action="store_true",
        help="If true, the new scan will be set as the branch's head scan"
    )

    parser.add_argument(
        "--generate-license",
        action="store_true",
        help="Generate license information"
    )

    parser.add_argument(
        "--enable-debug",
        action="store_true",
        help="Enable debug logging"
    )

    parser.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow unverified packages"
    )

    parser.add_argument(
        "--enable-json",
        action="store_true",
        help="Output in JSON format"
    )

    parser.add_argument(
        "--disable-overview",
        action="store_true",
        help="Disable overview output"
    )

    parser.add_argument(
        "--disable-security-issue",
        action="store_true",
        help="Disable security issue checks"
    )

    parser.add_argument(
        "--ignore-commit-files",
        action="store_true",
        help="Ignore commit files"
    )

    parser.add_argument(
        "--disable-blocking",
        action="store_true",
        help="Disable blocking mode"
    )

    # Path and file related arguments
    parser.add_argument(
        "--target-path",
        default="./",
        help="Target path for analysis"
    )

    parser.add_argument(
        "--scm",
        default="api",
        help="Source control management type"
    )

    parser.add_argument(
        "--sbom-file",
        help="SBOM file path"
    )

    parser.add_argument(
        "--commit-sha",
        default="",
        help="Commit SHA"
    )

    parser.add_argument(
        "--files",
        default="[]",
        help="Files to analyze (JSON array string)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout in seconds for API requests",
        required=False
    )

    return parser