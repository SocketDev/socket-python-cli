import json
import sys

from dotenv import load_dotenv
from git import InvalidGitRepositoryError, NoSuchPathError
from socketdev import socketdev

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, FullScanParams
from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.core.git_interface import Git
from socketsecurity.core.logging import initialize_logging, set_debug_mode
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments
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
        config = CliConfig.from_args()  # Get current config
        if not config.disable_blocking:
            sys.exit(3)
        else:
            sys.exit(0)


def main_code():
    config = CliConfig.from_args()
    output_handler = OutputHandler(blocking_disabled=config.disable_blocking)

    sdk = socketdev(token=config.api_token)

    if config.enable_debug:
        set_debug_mode(True)
        log.debug("Debug logging enabled")

    # Validate API token
    if not config.api_token:
        log.info("Unable to find Socket API Token")
        sys.exit(3)

    # Initialize Socket core components
    socket_config = SocketConfig(
        api_key=config.api_token,
        allow_unverified_ssl=config.allow_unverified
    )
    client = CliClient(socket_config)
    core = Core(socket_config, sdk)

    # Load files - files defaults to "[]" in CliConfig
    try:
        files = json.loads(config.files)  # Will always succeed with empty list by default
        is_repo = True  # FIXME: This is misleading - JSON parsing success doesn't indicate repo status
    except Exception as error:
        # Only hits this if files was manually set to invalid JSON
        log.error(f"Unable to parse {config.files}")
        log.error(error)
        sys.exit(3)

    # Git setup
    try:
        git_repo = Git(config.target_path)
        if not config.repo:
            config.repo = git_repo.repo_name
        if not config.commit_sha:
            config.commit_sha = git_repo.commit
        if not config.branch:
            config.branch = git_repo.branch
        if not config.committer:
            config.committer = git_repo.committer
        if not config.commit_message:
            config.commit_message = git_repo.commit_message
        if files and not config.ignore_commit_files:  # files is empty by default, so this is False unless files manually specified
            files = git_repo.changed_files  # Only gets git's changed files if files were manually specified
            is_repo = True  # Redundant since already True
    except InvalidGitRepositoryError:
        is_repo = False  # Overwrites previous True - this is the REAL repo status
        config.ignore_commit_files = True  # Silently changes config - should log this
    except NoSuchPathError:
        raise Exception(f"Unable to find path {config.target_path}")

    if not config.repo:
        log.info("Repo name needs to be set")
        sys.exit(2)

    scm = None
    if config.scm == "github":
        from socketsecurity.core.scm.github import Github, GithubConfig
        github_config = GithubConfig.from_env()
        scm = Github(client=client, config=github_config)
    elif config.scm == 'gitlab':
        from socketsecurity.core.scm.gitlab import Gitlab, GitlabConfig
        gitlab_config = GitlabConfig.from_env()
        scm = Gitlab(client=client, config=gitlab_config)
    if scm is not None:
        config.default_branch = scm.config.is_default_branch


    # Combine manually specified files with git changes if applicable
    files_to_check = set(json.loads(config.files))  # Start with manually specified files

    # Add git changes if this is a repo and we're not ignoring commit files
    if is_repo and not config.ignore_commit_files:
        files_to_check.update(git_repo.changed_files)

    # Determine if we need to scan based on manifest files
    should_skip_scan = True  # Default to skipping
    if config.ignore_commit_files:
        should_skip_scan = False  # Force scan if ignoring commit files
    elif files_to_check:  # If we have any files to check
        should_skip_scan = not core.has_manifest_files(list(files_to_check))

    if should_skip_scan:
        log.debug("No manifest files found in changes, skipping scan")
    else:
        log.debug("Found manifest files or forced scan, proceeding")

    params = FullScanParams(
        repo=config.repo,
        branch=config.branch,
        commit_message=config.commit_message,
        commit_hash=config.commit_sha,
        pull_request=config.pr_number,
        committers=config.committer,
        make_default_branch=config.default_branch, # This and
        set_as_pending_head=config.default_branch  # This are the same, do we need both?
    )

    # Initialize diff
    diff = Diff()
    diff.id = "NO_DIFF_RAN"

    # Handle SCM-specific flows
    if scm is not None and scm.check_event_type() == "comment":
        # FIXME: This entire flow should be a separate command called "filter_ignored_alerts_in_comments"
        # It's not related to scanning or diff generation - it just:
        # 1. Triggers on comments in GitHub/GitLab
        # 2. If comment was from Socket, checks for ignore reactions
        # 3. Updates the comment to remove ignored alerts
        # This is completely separate from the main scanning functionality
        log.info("Comment initiated flow")
        log.debug(f"Getting comments for Repo {scm.repository} for PR {scm.pr_number}")
        comments = scm.get_comments_for_pr(scm.repository, str(scm.pr_number))
        log.debug("Removing comment alerts")
        scm.remove_comment_alerts(comments)
    elif scm is not None and scm.check_event_type() != "comment":
        log.info("Push initiated flow")
        if should_skip_scan:
            log.info("No manifest files changes, skipping scan")
        elif scm.check_event_type() == "diff":
            diff = core.create_new_diff(config.target_path, params, workspace=config.target_path, no_change=should_skip_scan)
            log.info("Starting comment logic for PR/MR event")
            log.debug(f"Getting comments for Repo {scm.repository} for PR {scm.pr_number}")
            comments = scm.get_comments_for_pr(config.repo, str(config.pr_number))
            log.debug("Removing comment alerts")
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
            if (len(diff.new_packages) == 0 and len(diff.removed_packages) == 0) or config.disable_overview:
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
            diff = core.create_new_diff(config.target_path, params, workspace=config.target_path, no_change=should_skip_scan)

        # Use output handler for results
        if config.enable_json:
            log.debug("Outputting JSON Results")
            output_handler.output_console_json(diff, config.sbom_file)
        else:
            output_handler.output_console_comments(diff, config.sbom_file)
    else:
        log.info("API Mode")
        diff = core.create_new_diff(config.target_path, params, workspace=config.target_path, no_change=should_skip_scan)
        if config.enable_json:
            output_handler.output_console_json(diff, config.sbom_file)
        else:
            output_handler.output_console_comments(diff, config.sbom_file)

    # Handle license generation
    if diff is not None and config.generate_license:
        all_packages = {}
        for package_id in diff.packages:
            package = diff.packages[package_id]
            output = {
                "id": package_id,
                "name": package.name,
                "version": package.version,
                "ecosystem": package.type,
                "direct": package.direct,
                "url": package.url,
                "license": package.license,
                "license_text": package.license_text
            }
            all_packages[package_id] = output
        license_file = f"{config.repo}"
        if config.branch:
            license_file += f"_{config.branch}"
        license_file += ".json"
        core.save_file(license_file, json.dumps(all_packages))


if __name__ == '__main__':
    cli()
