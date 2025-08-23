import json
import sys
import traceback

from dotenv import load_dotenv
from git import InvalidGitRepositoryError, NoSuchPathError
from socketdev import socketdev
from socketdev.fullscans import FullScanParams
from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff
from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.git_interface import Git
from socketsecurity.core.logging import initialize_logging, set_debug_mode
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.output import OutputHandler

socket_logger, log = initialize_logging()

load_dotenv()

def cli():
    try:
        main_code()
    except KeyboardInterrupt:
        log.info("Keyboard Interrupt detected, exiting")
        config = CliConfig.from_args()  # Get current config
        if not config.disable_blocking:
            sys.exit(2)
        else:
            sys.exit(0)
    except Exception as error:
        log.error("Unexpected error when running the cli")
        log.error(error)
        traceback.print_exc()
        config = CliConfig.from_args()  # Get current config
        if not config.disable_blocking:
            sys.exit(3)
        else:
            sys.exit(0)


def main_code():
    config = CliConfig.from_args()
    log.info(f"Starting Socket Security CLI version {config.version}")
    log.debug(f"config: {config.to_dict()}")
    
    # Validate API token
    if not config.api_token:
        log.info("Socket API Token not found. Please set it using either:\n"
                 "1. Command line: --api-token YOUR_TOKEN\n"
                 "2. Environment variable: SOCKET_SECURITY_API_KEY")
        sys.exit(3)
    
    sdk = socketdev(token=config.api_token)
    output_handler = OutputHandler(config, sdk)
    log.debug("sdk loaded")

    if config.enable_debug:
        set_debug_mode(True)
        log.debug("Debug logging enabled")


    # Initialize Socket core components
    socket_config = SocketConfig(
        api_key=config.api_token,
        allow_unverified_ssl=config.allow_unverified,
        timeout=config.timeout if config.timeout is not None else 1200  # Use CLI timeout if provided
    )
    log.debug("loaded socket_config")
    client = CliClient(socket_config)
    sdk.api.api_url = socket_config.api_url
    log.debug("loaded client")
    core = Core(socket_config, sdk)
    log.debug("loaded core")
    # Parse files argument
    try:
        if isinstance(config.files, list):
            # Already a list, use as-is
            specified_files = config.files
        elif isinstance(config.files, str):
            # Handle different string formats
            files_str = config.files.strip()
            
            # If the string is wrapped in extra quotes, strip them
            if ((files_str.startswith('"') and files_str.endswith('"')) or 
                (files_str.startswith("'") and files_str.endswith("'"))):
                # Check if the inner content looks like JSON
                inner_str = files_str[1:-1]
                if inner_str.startswith('[') and inner_str.endswith(']'):
                    files_str = inner_str
            
            # Try to parse as JSON
            try:
                specified_files = json.loads(files_str)
            except json.JSONDecodeError:
                # If JSON parsing fails, try replacing single quotes with double quotes
                files_str = files_str.replace("'", '"')
                specified_files = json.loads(files_str)
        else:
            # Default to empty list
            specified_files = []
    except Exception as error:
        log.error(f"Unable to parse files argument: {config.files}")
        log.error(f"Error details: {error}")
        log.debug(f"Files type: {type(config.files)}")
        log.debug(f"Files repr: {repr(config.files)}")
        sys.exit(3)

    # Determine if files were explicitly specified
    files_explicitly_specified = config.files != "[]" and len(specified_files) > 0
    
    # Git setup
    is_repo = False
    git_repo = None
    try:
        git_repo = Git(config.target_path)
        is_repo = True
        if not config.repo:
            config.repo = git_repo.repo_name
        if not config.commit_sha:
            config.commit_sha = git_repo.commit_str
        if not config.branch:
            config.branch = git_repo.branch
        if not config.committers:
            config.committers = [git_repo.get_formatted_committer()]
        if not config.commit_message:
            config.commit_message = git_repo.commit_message
    except InvalidGitRepositoryError:
        is_repo = False
        log.debug("Not a git repository, setting ignore_commit_files=True")
        config.ignore_commit_files = True
    except NoSuchPathError:
        raise Exception(f"Unable to find path {config.target_path}")

    if not config.repo:
        config.repo = "socket-default-repo"
        log.debug(f"Using default repository name: {config.repo}")
        
    if not config.branch:
        config.branch = "socket-default-branch"
        log.debug(f"Using default branch name: {config.branch}")

    scm = None
    if config.scm == "github":
        from socketsecurity.core.scm.github import Github, GithubConfig
        # Only pass pr_number if it's not "0" (the default)
        pr_number = config.pr_number if config.pr_number != "0" else None
        github_config = GithubConfig.from_env(pr_number=pr_number)
        scm = Github(client=client, config=github_config)
    elif config.scm == 'gitlab':
        from socketsecurity.core.scm.gitlab import Gitlab, GitlabConfig
        gitlab_config = GitlabConfig.from_env()
        scm = Gitlab(client=client, config=gitlab_config)
    # Don't override config.default_branch if it was explicitly set via --default-branch flag
    # Only use SCM detection if --default-branch wasn't provided
    if scm is not None and not config.default_branch:
        config.default_branch = scm.config.is_default_branch

    # Determine files to check based on the new logic
    files_to_check = []
    force_api_mode = False
    
    if files_explicitly_specified:
        # Case 2: Files are specified - use them and don't check commit details
        files_to_check = specified_files
        log.debug(f"Using explicitly specified files: {files_to_check}")
    elif not config.ignore_commit_files and is_repo:
        # Case 1: Files not specified and --ignore-commit-files not set - try to find changed files from commit
        files_to_check = git_repo.changed_files
        log.debug(f"Using changed files from commit: {files_to_check}")
    else:
        # ignore_commit_files is set or not a repo - scan everything but force API mode if no supported files
        files_to_check = []
        log.debug("No files to check from commit (ignore_commit_files=True or not a repo)")

    # Check if we have supported manifest files
    has_supported_files = files_to_check and core.has_manifest_files(files_to_check)
    
    # Case 3: If no supported files or files are empty, force API mode (no PR comments)
    if not has_supported_files:
        force_api_mode = True
        log.debug("No supported manifest files found, forcing API mode")
    
    # Determine scan behavior
    should_skip_scan = False  # Always perform scan, but behavior changes based on supported files
    if config.ignore_commit_files and not files_explicitly_specified:
        # Force full scan when ignoring commit files and no explicit files
        should_skip_scan = False
        log.debug("Forcing full scan due to ignore_commit_files")
    elif not has_supported_files:
        # No supported files - still scan but in API mode
        should_skip_scan = False
        log.debug("No supported files but will scan in API mode")
    else:
        log.debug("Found supported manifest files, proceeding with normal scan")

    org_slug = core.config.org_slug
    if config.repo_is_public:
        core.config.repo_visibility = "public"
    if config.excluded_ecosystems and len(config.excluded_ecosystems) > 0:
        core.config.excluded_ecosystems = config.excluded_ecosystems
    integration_type = config.integration_type
    integration_org_slug = config.integration_org_slug or org_slug
    try:
        pr_number = int(config.pr_number)
    except (ValueError, TypeError):
        pr_number = 0

    # Determine if this should be treated as default branch
    # Priority order:
    # 1. If --default-branch flag is explicitly set to True, use that
    # 2. If SCM detected it's the default branch, use that
    # 3. If it's a git repo, use git_repo.is_default_branch
    # 4. Otherwise, default to False
    if config.default_branch:
        is_default_branch = True
    elif scm is not None and hasattr(scm.config, 'is_default_branch') and scm.config.is_default_branch:
        is_default_branch = True
    elif is_repo and git_repo.is_default_branch:
        is_default_branch = True
    else:
        is_default_branch = False

    params = FullScanParams(
        org_slug=org_slug,
        integration_type=integration_type,
        integration_org_slug=integration_org_slug,
        repo=config.repo,
        branch=config.branch,
        commit_message=config.commit_message,
        commit_hash=config.commit_sha,
        pull_request=pr_number,
        committers=config.committers,
        make_default_branch=is_default_branch,
        set_as_pending_head=is_default_branch
    )

    params.include_license_details = not config.exclude_license_details

    # Initialize diff
    diff = Diff()
    diff.id = "NO_DIFF_RAN"
    diff.diff_url = ""
    diff.report_url = ""

    # Handle SCM-specific flows
    if scm is not None and scm.check_event_type() == "comment":
        # FIXME: This entire flow should be a separate command called "filter_ignored_alerts_in_comments"
        # It's not related to scanning or diff generation - it just:
        # 1. Triggers on comments in GitHub/GitLab
        # 2. If comment was from Socket, checks for ignore reactions
        # 3. Updates the comment to remove ignored alerts
        # This is completely separate from the main scanning functionality
        log.info("Comment initiated flow")
        
        comments = scm.get_comments_for_pr()
        log.debug("Removing comment alerts")
        scm.remove_comment_alerts(comments)
    
    elif scm is not None and scm.check_event_type() != "comment" and not force_api_mode:
        log.info("Push initiated flow")
        if scm.check_event_type() == "diff":
            log.info("Starting comment logic for PR/MR event")
            diff = core.create_new_diff(config.target_path, params, no_change=should_skip_scan, save_files_list_path=config.save_submitted_files_list, save_manifest_tar_path=config.save_manifest_tar)
            comments = scm.get_comments_for_pr()
            log.debug("Removing comment alerts")
            
            # FIXME: this overwrites diff.new_alerts, which was previously populated by Core.create_issue_alerts
            diff.new_alerts = Comments.remove_alerts(comments, diff.new_alerts)
            log.debug("Creating Dependency Overview Comment")
            
            overview_comment = Messages.dependency_overview_template(diff)
            log.debug("Creating Security Issues Comment")
            
            security_comment = Messages.security_comment_template(diff)
            
            new_security_comment = True
            new_overview_comment = True
            
            update_old_security_comment = (
                security_comment is None or
                security_comment == "" or
                (len(comments) != 0 and comments.get("security") is not None)
            )
            
            update_old_overview_comment = (
                overview_comment is None or
                overview_comment == "" or
                (len(comments) != 0 and comments.get("overview") is not None)
            )
            
            if len(diff.new_alerts) == 0 or config.disable_security_issue:
                if not update_old_security_comment:
                    new_security_comment = False
                    log.debug("No new alerts or security issue comment disabled")
                else:
                    log.debug("Updated security comment with no new alerts")
            
            # FIXME: diff.new_packages is never populated, neither is removed_packages
            if (len(diff.new_packages) == 0) or config.disable_overview:
                if not update_old_overview_comment:
                    new_overview_comment = False
                    log.debug("No new/removed packages or Dependency Overview comment disabled")
                else:
                    log.debug("Updated overview comment with no dependencies")
            
            log.debug(f"Adding comments for {config.scm}")
            scm.add_socket_comments(
                security_comment,
                overview_comment,
                comments,
                new_security_comment,
                new_overview_comment
            )
        else:
            log.info("Starting non-PR/MR flow")
            diff = core.create_new_diff(config.target_path, params, no_change=should_skip_scan, save_files_list_path=config.save_submitted_files_list, save_manifest_tar_path=config.save_manifest_tar)

        output_handler.handle_output(diff)
    
    elif config.enable_diff and not force_api_mode:
        # New logic: --enable-diff forces diff mode even with --integration api (no SCM)
        log.info("Diff mode enabled without SCM integration")
        diff = core.create_new_diff(config.target_path, params, no_change=should_skip_scan, save_files_list_path=config.save_submitted_files_list, save_manifest_tar_path=config.save_manifest_tar)
        output_handler.handle_output(diff)
    
    elif config.enable_diff and force_api_mode:
        # User requested diff mode but no manifest files were detected
        log.warning("--enable-diff was specified but no supported manifest files were detected in the changed files. Falling back to full scan mode.")
        log.info("Creating Socket Report (full scan)")
        serializable_params = {
            key: value if isinstance(value, (int, float, str, list, dict, bool, type(None))) else str(value)
            for key, value in params.__dict__.items()
        }
        log.debug(f"params={serializable_params}")
        diff = core.create_full_scan_with_report_url(
            config.target_path,
            params,
            no_change=should_skip_scan,
            save_files_list_path=config.save_submitted_files_list,
            save_manifest_tar_path=config.save_manifest_tar
        )
        log.info(f"Full scan created with ID: {diff.id}")
        log.info(f"Full scan report URL: {diff.report_url}")
        output_handler.handle_output(diff)
    
    else:
        if force_api_mode:
            log.info("No Manifest files changed, creating Socket Report")
            serializable_params = {
                key: value if isinstance(value, (int, float, str, list, dict, bool, type(None))) else str(value)
                for key, value in params.__dict__.items()
            }
            log.debug(f"params={serializable_params}")
            diff = core.create_full_scan_with_report_url(
                config.target_path,
                params,
                no_change=should_skip_scan,
                save_files_list_path=config.save_submitted_files_list,
                save_manifest_tar_path=config.save_manifest_tar
            )
            log.info(f"Full scan created with ID: {diff.id}")
            log.info(f"Full scan report URL: {diff.report_url}")
        else:
            log.info("API Mode")
            diff = core.create_new_diff(
                config.target_path, params,
                no_change=should_skip_scan,
                save_files_list_path=config.save_submitted_files_list,
                save_manifest_tar_path=config.save_manifest_tar
            )
            output_handler.handle_output(diff)

        # Handle license generation
    if not should_skip_scan and diff.id != "NO_DIFF_RAN" and diff.id != "NO_SCAN_RAN" and config.generate_license:
        all_packages = {}
        for purl in diff.packages:
            package = diff.packages[purl]
            output = {
                "id": package.id,
                "name": package.name,
                "version": package.version,
                "ecosystem": package.type,
                "direct": package.direct,
                "url": package.url,
                "license": package.license,
                "licenseDetails": package.licenseDetails,
                "licenseAttrib": package.licenseAttrib,
                "purl": package.purl,
            }
            all_packages[package.id] = output
        core.save_file(config.license_file_name, json.dumps(all_packages))

    # If we forced API mode due to no supported files, behave as if --disable-blocking was set
    if force_api_mode and not config.disable_blocking:
        log.debug("Temporarily enabling disable_blocking due to no supported manifest files")
        config.disable_blocking = True

    sys.exit(output_handler.return_exit_code(diff))


if __name__ == '__main__':
    cli()
