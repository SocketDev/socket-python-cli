import json
import os
import sys
import traceback
import shutil
import warnings

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
                 "2. Environment variable: SOCKET_SECURITY_API_TOKEN")
        sys.exit(3)
    cli_user_agent_string = f"SocketPythonCLI/{config.version}"
    sdk = socketdev(token=config.api_token, allow_unverified=config.allow_unverified, user_agent=cli_user_agent_string)
    
    # Suppress urllib3 InsecureRequestWarning when using --allow-unverified
    if config.allow_unverified:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
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
    core = Core(socket_config, sdk, config)
    log.debug("loaded core")
    
    # Check for required dependencies if reachability analysis is enabled
    if config.reach:
        log.info("Reachability analysis enabled, checking for required dependencies...")
        required_deps = ["npm", "uv", "npx"]
        missing_deps = []
        found_deps = []
        
        for dep in required_deps:
            if shutil.which(dep):
                found_deps.append(dep)
                log.debug(f"Found required dependency: {dep}")
            else:
                missing_deps.append(dep)
        
        if missing_deps:
            log.error(f"Reachability analysis requires the following dependencies: {', '.join(required_deps)}")
            log.error(f"Missing dependencies: {', '.join(missing_deps)}")
            log.error("Please install the missing dependencies and try again.")
            sys.exit(3)
        
        log.info(f"All required dependencies found: {', '.join(found_deps)}")
        
        # Check if organization has an enterprise plan
        log.info("Checking organization plan for reachability analysis eligibility...")
        org_response = sdk.org.get(use_types=True)
        organizations = org_response.get("organizations", {})
        
        if organizations:
            org_id = next(iter(organizations))
            org_plan = organizations[org_id].get('plan', '')
            
            # Check if plan matches enterprise* pattern (enterprise, enterprise_trial, etc.)
            if not org_plan.startswith('enterprise'):
                log.error(f"Reachability analysis is only available for enterprise plans.")
                log.error(f"Your organization plan is: {org_plan}")
                log.error("Please upgrade to an enterprise plan to use reachability analysis.")
                sys.exit(3)
            
            log.info(f"Organization plan verified: {org_plan}")
        else:
            log.error("Unable to retrieve organization information for plan verification.")
            sys.exit(3)
    
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
    
    # Variable to track if we need to override files with facts file
    facts_file_to_submit = None
    # Variable to track SBOM files to submit when using --reach-use-only-pregenerated-sboms
    sbom_files_to_submit = None
    
    # Git setup
    is_repo = False
    git_repo: Git
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
        base_repo_name = "socket-default-repo"
        if config.workspace_name:
            config.repo = f"{base_repo_name}-{config.workspace_name}"
        else:
            config.repo = base_repo_name
        log.debug(f"Using default repository name: {config.repo}")
        
    if not config.branch:
        config.branch = "socket-default-branch"
        log.debug(f"Using default branch name: {config.branch}")

    # Calculate the scan paths - combine target_path with sub_paths if provided
    scan_paths = []
    base_paths = [config.target_path]  # Always use target_path as the single base path
    
    if config.sub_paths:
        for sub_path in config.sub_paths:
            full_scan_path = os.path.join(config.target_path, sub_path)
            log.debug(f"Using sub-path for scanning: {full_scan_path}")
            # Verify the scan path exists
            if not os.path.exists(full_scan_path):
                raise Exception(f"Sub-path does not exist: {full_scan_path}")
            scan_paths.append(full_scan_path)
    else:
        # Use the target path as the single scan path
        scan_paths = [config.target_path]

    # Modify repository name if workspace_name is provided
    if config.workspace_name and config.repo:
        config.repo = f"{config.repo}-{config.workspace_name}"
        log.debug(f"Modified repository name with workspace suffix: {config.repo}")
    elif config.workspace_name and not config.repo:
        # If no repo name was set but workspace_name is provided, we'll use it later
        log.debug(f"Workspace name provided: {config.workspace_name}")

    # Run reachability analysis if enabled
    if config.reach:
        from socketsecurity.core.tools.reachability import ReachabilityAnalyzer

        log.info("Starting reachability analysis...")

        # Find manifest files in scan paths (excluding .socket.facts.json to avoid circular dependency)
        log.info("Finding manifest files for reachability analysis...")
        manifest_files = []

        # Always find all manifest files for the tar hash upload
        for scan_path in scan_paths:
            scan_manifests = core.find_files(scan_path)
            # Filter out .socket.facts.json files from manifest upload
            scan_manifests = [f for f in scan_manifests if not f.endswith('.socket.facts.json')]
            manifest_files.extend(scan_manifests)
        
        if not manifest_files:
            log.warning("No manifest files found for reachability analysis")
        else:
            log.info(f"Found {len(manifest_files)} manifest files for reachability upload")
            
            # Upload manifests and get tar hash
            log.info("Uploading manifest files...")
            try:
                # Get org_slug early (we'll need it)
                org_slug = core.config.org_slug
                
                # Upload manifest files
                tar_hash = sdk.uploadmanifests.upload_manifest_files(
                    org_slug=org_slug,
                    file_paths=manifest_files,
                    workspace=config.repo or "default-workspace",
                    base_paths=[config.target_path],
                    use_lazy_loading=False
                )
                log.info(f"Manifest upload successful, tar hash: {tar_hash}")
                
                # Initialize and run reachability analyzer
                analyzer = ReachabilityAnalyzer(sdk, config.api_token)
                
                # Determine output path
                output_path = config.reach_output_file or ".socket.facts.json"
                
                # Run the analysis
                result = analyzer.run_reachability_analysis(
                    org_slug=org_slug,
                    target_directory=config.target_path,
                    tar_hash=tar_hash,
                    output_path=output_path,
                    timeout=config.reach_analysis_timeout,
                    memory_limit=config.reach_analysis_memory_limit,
                    ecosystems=config.reach_ecosystems,
                    exclude_paths=config.reach_exclude_paths,
                    min_severity=config.reach_min_severity,
                    skip_cache=config.reach_skip_cache or False,
                    disable_analytics=config.reach_disable_analytics or False,
                    disable_analysis_splitting=config.reach_disable_analysis_splitting or False,
                    repo_name=config.repo,
                    branch_name=config.branch,
                    version=config.reach_version,
                    concurrency=config.reach_concurrency,
                    additional_params=config.reach_additional_params,
                    allow_unverified=config.allow_unverified,
                    enable_debug=config.enable_debug,
                    use_only_pregenerated_sboms=config.reach_use_only_pregenerated_sboms
                )
                
                log.info(f"Reachability analysis completed successfully")
                log.info(f"Results written to: {result['report_path']}")
                if result.get('scan_id'):
                    log.info(f"Reachability scan ID: {result['scan_id']}")
                
                # If only-facts-file mode, mark the facts file for submission
                if config.only_facts_file:
                    facts_file_to_submit = os.path.abspath(output_path)
                    log.info(f"Only-facts-file mode: will submit only {facts_file_to_submit}")

                # If reach-use-only-pregenerated-sboms mode, submit CDX, SPDX, and facts file
                if config.reach_use_only_pregenerated_sboms:
                    # Find only CDX and SPDX files for the final scan submission
                    sbom_files_to_submit = []
                    for scan_path in scan_paths:
                        sbom_files_to_submit.extend(core.find_sbom_files(scan_path))
                    # Use relative path for facts file
                    if os.path.exists(output_path):
                        sbom_files_to_submit.append(output_path)
                    log.info(f"Pre-generated SBOMs mode: will submit {len(sbom_files_to_submit)} files (CDX, SPDX, and facts file)")
                
            except Exception as e:
                log.error(f"Reachability analysis failed: {str(e)}")
                if not config.disable_blocking:
                    sys.exit(3)
        
        log.info("Continuing with normal scan flow...")

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

    # Override files if only-facts-file mode is active
    if facts_file_to_submit:
        specified_files = [facts_file_to_submit]
        files_explicitly_specified = True
        log.debug(f"Overriding files to only submit facts file: {facts_file_to_submit}")

    # Override files if reach-use-only-pregenerated-sboms mode is active
    if sbom_files_to_submit:
        specified_files = sbom_files_to_submit
        files_explicitly_specified = True
        log.debug(f"Overriding files to submit only SBOM files (CDX, SPDX, and facts): {sbom_files_to_submit}")

    # Determine files to check based on the new logic
    files_to_check = []
    force_api_mode = False
    force_diff_mode = False
    
    if files_explicitly_specified:
        # Case 2: Files are specified - use them and don't check commit details
        files_to_check = specified_files
        log.debug(f"Using explicitly specified files: {files_to_check}")
    elif not config.ignore_commit_files and is_repo:
        # Case 1: Files not specified and --ignore-commit-files not set - try to find changed files from commit
        files_to_check = git_repo.changed_files
        log.debug(f"Using changed files from commit: {files_to_check}")
    elif config.ignore_commit_files and is_repo:
        # Case 3: Git repo with --ignore-commit-files - force diff mode
        files_to_check = []
        force_diff_mode = True
        log.debug("Git repo with --ignore-commit-files: forcing diff mode")
    else:
        # Case 4: Not a git repo (ignore_commit_files was auto-set to True)
        files_to_check = []
        # If --enable-diff is set, force diff mode for non-git repos
        log.debug(f"Case 4: Non-git repo - config.enable_diff={config.enable_diff}, type={type(config.enable_diff)}")
        if config.enable_diff:
            force_diff_mode = True
            log.debug("Non-git repo with --enable-diff: forcing diff mode")
        else:
            log.debug("Non-git repo without --enable-diff: will use full scan mode")

    # Check if we have supported manifest files
    has_supported_files = files_to_check and core.has_manifest_files(files_to_check)
    
    # If using sub_paths, we need to check if manifest files exist in the scan paths
    if config.sub_paths and not files_explicitly_specified:
        # Override file checking to look in the scan paths instead
        # Get manifest files from all scan paths
        try:
            all_scan_files = []
            for scan_path in scan_paths:
                scan_files = core.find_files(scan_path)
                all_scan_files.extend(scan_files)
            has_supported_files = len(all_scan_files) > 0
            log.debug(f"Found {len(all_scan_files)} manifest files across {len(scan_paths)} scan paths")
        except Exception as e:
            log.debug(f"Error finding files in scan paths: {e}")
            has_supported_files = False
    
    # Case 3: If no supported files or files are empty, force API mode (no PR comments)
    # BUT: Don't force API mode if we're in force_diff_mode
    log.debug(f"files_to_check={files_to_check}, has_supported_files={has_supported_files}, force_diff_mode={force_diff_mode}, config.enable_diff={config.enable_diff}")
    if not has_supported_files and not force_diff_mode:
        force_api_mode = True
        log.debug("No supported manifest files found, forcing API mode")
    log.debug(f"force_api_mode={force_api_mode}")
    
    # Determine scan behavior
    should_skip_scan = False  # Always perform scan, but behavior changes based on supported files
    if not has_supported_files and not force_diff_mode:
        # No supported files and not forcing diff - still scan but in API mode
        should_skip_scan = False
        log.debug("No supported files but will scan in API mode")
    else:
        log.debug("Found supported manifest files or forcing diff mode, proceeding with normal scan")

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
        set_as_pending_head=is_default_branch,
        tmp=False
    )

    params.include_license_details = not config.exclude_license_details

    # Initialize diff
    diff = Diff()
    diff.id = "NO_DIFF_RAN"
    diff.diff_url = ""
    diff.report_url = ""

    # Handle SCM-specific flows
    log.debug(f"Flow decision: scm={scm is not None}, force_diff_mode={force_diff_mode}, force_api_mode={force_api_mode}, enable_diff={config.enable_diff}")
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
            diff = core.create_new_diff(scan_paths, params, no_change=should_skip_scan, save_files_list_path=config.save_submitted_files_list, save_manifest_tar_path=config.save_manifest_tar, base_paths=base_paths, explicit_files=sbom_files_to_submit)
            comments = scm.get_comments_for_pr()
            log.debug("Removing comment alerts")
            
            # FIXME: this overwrites diff.new_alerts, which was previously populated by Core.create_issue_alerts
            diff.new_alerts = Comments.remove_alerts(comments, diff.new_alerts)
            log.debug("Creating Dependency Overview Comment")
            
            overview_comment = Messages.dependency_overview_template(diff)
            log.debug("Creating Security Issues Comment")
            
            security_comment = Messages.security_comment_template(diff, config)
            
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
            diff = core.create_new_diff(scan_paths, params, no_change=should_skip_scan, save_files_list_path=config.save_submitted_files_list, save_manifest_tar_path=config.save_manifest_tar, base_paths=base_paths, explicit_files=sbom_files_to_submit)

        output_handler.handle_output(diff)

    elif (config.enable_diff or force_diff_mode) and not force_api_mode:
        # New logic: --enable-diff or force_diff_mode (from --ignore-commit-files in git repos) forces diff mode
        log.info("Diff mode enabled without SCM integration")
        diff = core.create_new_diff(scan_paths, params, no_change=should_skip_scan, save_files_list_path=config.save_submitted_files_list, save_manifest_tar_path=config.save_manifest_tar, base_paths=base_paths, explicit_files=sbom_files_to_submit)
        output_handler.handle_output(diff)
    
    elif (config.enable_diff or force_diff_mode) and force_api_mode:
        # User requested diff mode but no manifest files were detected - this should not happen with new logic
        # but keeping as a safety net
        log.warning("--enable-diff was specified but no supported manifest files were detected in the changed files. Falling back to full scan mode.")
        log.info("Creating Socket Report (full scan)")
        serializable_params = {
            key: value if isinstance(value, (int, float, str, list, dict, bool, type(None))) else str(value)
            for key, value in params.__dict__.items()
        }
        log.debug(f"params={serializable_params}")
        diff = core.create_full_scan_with_report_url(
            scan_paths,
            params,
            no_change=should_skip_scan,
            save_files_list_path=config.save_submitted_files_list,
            save_manifest_tar_path=config.save_manifest_tar,
            base_paths=base_paths,
            explicit_files=sbom_files_to_submit
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
                scan_paths,
                params,
                no_change=should_skip_scan,
                save_files_list_path=config.save_submitted_files_list,
                save_manifest_tar_path=config.save_manifest_tar,
                base_paths=base_paths,
                explicit_files=sbom_files_to_submit
            )
            log.info(f"Full scan created with ID: {diff.id}")
            log.info(f"Full scan report URL: {diff.report_url}")
            output_handler.handle_output(diff)
        else:
            log.info("API Mode")
            diff = core.create_new_diff(
                scan_paths, params,
                no_change=should_skip_scan,
                save_files_list_path=config.save_submitted_files_list,
                save_manifest_tar_path=config.save_manifest_tar,
                base_paths=base_paths,
                explicit_files=sbom_files_to_submit
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
