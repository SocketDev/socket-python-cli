import argparse
import json

import socketsecurity.core
from socketsecurity.core import Core, __version__
from socketsecurity.core.classes import FullScanParams, Diff, Package, Issue
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments
from socketsecurity.core.git_interface import Git
from git import InvalidGitRepositoryError, NoSuchPathError
import os
import sys
import logging

log_format = "%(asctime)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=log_format)
socketsecurity.core.log.setLevel(level=logging.INFO)
log = logging.getLogger("socketcli")
blocking_disabled = False

parser = argparse.ArgumentParser(
    prog="socketcli",
    description="Socket Security CLI"
)
parser.add_argument(
    '--api_token',
    help='The Socket API token can be set via SOCKET_SECURITY_API_KEY',
    required=False
)
parser.add_argument(
    '--repo',
    help='The name of the repository',
    required=False
)
parser.add_argument(
    '--branch',
    default='',
    help='The name of the branch',
    required=False
)
parser.add_argument(

    '--committer',
    help='The name of the person or bot running this',
    action="append",
    required=False
)
parser.add_argument(
    '--pr_number',
    default="0",
    help='The pr or build number',
    required=False
)
parser.add_argument(
    '--commit_message',
    help='Commit or build message for the run',
    required=False
)
parser.add_argument(
    '--default_branch',
    default=False,
    action='store_true',
    help='Whether this is the default/head for run'
)
parser.add_argument(
    '--target_path',
    default='./',
    help='Path to look for manifest files',
    required=False
)

parser.add_argument(
    '--scm',
    default='api',
    help='Integration mode choices are api, github, gitlab, and bitbucket',
    choices=["api", "github", "gitlab"],
    required=False
)

parser.add_argument(
    '--sbom-file',
    default=None,
    help='If soecified save the SBOM details to the specified file',
    required=False
)

parser.add_argument(
    '--commit-sha',
    default="",
    help='Optional git commit sha',
    required=False
)

parser.add_argument(
    '--generate-license',
    default=False,
    help='Run in license mode to generate license output',
    required=False
)

parser.add_argument(
    '-v',
    '--version',
    action="version",
    version=f'%(prog)s {__version__}',
    help='Display the version',
)

parser.add_argument(
    '--enable-debug',
    help='Enable debug mode',
    action='store_true',
    default=False
)

parser.add_argument(
    '--allow-unverified',
    help='Allow unverified SSL Connections',
    action='store_true',
    default=False
)

parser.add_argument(
    '--enable-json',
    help='Enable json output of results instead of table formatted',
    action='store_true',
    default=False
)

parser.add_argument(
    '--disable-overview',
    help='Disables Dependency Overview comments',
    action='store_true',
    default=False
)

parser.add_argument(
    '--disable-security-issue',
    help='Disables Security Issues comment',
    action='store_true',
    default=False
)

parser.add_argument(
    '--files',
    help='Specify a list of files in the format of ["file1", "file2"]',
    default="[]"
)

parser.add_argument(
    '--ignore-commit-files',
    help='Ignores only looking for changed files form the commit. Will find any supported manifest file type',
    action='store_true',
    default=False
)

parser.add_argument(
    '--disable-blocking',
    help='Disables failing checks and will only exit with an exit code of 0',
    action='store_true',
    default=False
)


def output_console_comments(diff_report: Diff, sbom_file_name: str = None) -> None:
    if diff_report.id != "NO_DIFF_RAN":
        console_security_comment = Messages.create_console_security_alert_table(diff_report)
        save_sbom_file(diff_report, sbom_file_name)
        log.info(f"Socket Full Scan ID: {diff_report.id}")
        if len(diff_report.new_alerts) > 0:
            log.info("Security issues detected by Socket Security")
            msg = f"\n{console_security_comment}"
            log.info(msg)
            if not report_pass(diff_report) and not blocking_disabled:
                sys.exit(1)
            else:
                # Means only warning alerts with no blocked
                if not blocking_disabled:
                    sys.exit(5)
        else:
            log.info("No New Security issues detected by Socket Security")


def output_console_json(diff_report: Diff, sbom_file_name: str = None) -> None:
    if diff_report.id != "NO_DIFF_RAN":
        console_security_comment = Messages.create_security_comment_json(diff_report)
        save_sbom_file(diff_report, sbom_file_name)
        print(json.dumps(console_security_comment))
        if not report_pass(diff_report) and not blocking_disabled:
            sys.exit(1)
        elif len(diff_report.new_alerts) > 0 and not blocking_disabled:
            # Means only warning alerts with no blocked
            sys.exit(5)


def report_pass(diff_report: Diff) -> bool:
    report_passed = True
    if len(diff_report.new_alerts) > 0:
        for alert in diff_report.new_alerts:
            alert: Issue
            if report_passed and alert.error:
                report_passed = False
                break
    return report_passed


def save_sbom_file(diff_report: Diff, sbom_file_name: str = None):
    if diff_report is not None and sbom_file_name is not None:
        Core.save_file(sbom_file_name, json.dumps(Core.create_sbom_output(diff_report)))


def cli():
    try:
        main_code()
    except KeyboardInterrupt:
        log.info("Keyboard Interrupt detected, exiting")
        if not blocking_disabled:
            sys.exit(2)
        else:
            sys.exit(0)
    except Exception as error:
        log.error("Unexpected error when running the cli")
        log.error(error)
        if not blocking_disabled:
            sys.exit(3)
        else:
            sys.exit(0)


def main_code():
    arguments = parser.parse_args()
    debug = arguments.enable_debug
    if debug:
        logging.basicConfig(level=logging.DEBUG, format=log_format)
        log.setLevel(logging.DEBUG)
        Core.enable_debug_log(logging.DEBUG)
        log.debug("Debug logging enabled")
    repo = arguments.repo
    branch = arguments.branch
    commit_message = arguments.commit_message
    committer = arguments.committer
    default_branch = arguments.default_branch
    pr_number = arguments.pr_number
    target_path = arguments.target_path
    scm_type = arguments.scm
    commit_sha = arguments.commit_sha
    sbom_file = arguments.sbom_file
    license_mode = arguments.generate_license
    enable_json = arguments.enable_json
    disable_overview = arguments.disable_overview
    disable_security_issue = arguments.disable_security_issue
    ignore_commit_files = arguments.ignore_commit_files
    disable_blocking = arguments.disable_blocking
    allow_unverified = arguments.allow_unverified
    if disable_blocking:
        global blocking_disabled
        blocking_disabled = True
    files = arguments.files
    log.info(f"Starting Socket Security Scan version {__version__}")
    api_token = os.getenv("SOCKET_SECURITY_API_KEY") or arguments.api_token
    try:
        files = json.loads(files)
        is_repo = True
    except Exception as error:
        log.error(f"Unable to parse {files}")
        log.error(error)
        sys.exit(3)
    if api_token is None:
        log.info("Unable to find Socket API Token")
        sys.exit(3)
    try:
        git_repo = Git(target_path)
        if repo is None:
            repo = git_repo.repo_name
        if commit_sha is None or commit_sha == '':
            commit_sha = git_repo.commit
        if branch is None or branch == '':
            branch = git_repo.branch
        if committer is None or committer == '':
            committer = git_repo.committer
        if commit_message is None or commit_message == '':
            commit_message = git_repo.commit_message
        if len(files) == 0 and not ignore_commit_files:
            files = git_repo.changed_files
            is_repo = True
    except InvalidGitRepositoryError:
        is_repo = False
        ignore_commit_files = True
        pass
    except NoSuchPathError:
        raise Exception(f"Unable to find path {target_path}")
        # git_repo = None
    if repo is None:
        log.info("Repo name needs to be set")
        sys.exit(2)
    license_file = f"{repo}"
    if branch is not None:
        license_file += f"_{branch}"
    license_file += ".json"
    scm = None
    if scm_type == "github":
        from socketsecurity.core.github import Github
        scm = Github()
    elif scm_type == 'gitlab':
        from socketsecurity.core.gitlab import Gitlab
        scm = Gitlab()
    if scm is not None:
        default_branch = scm.is_default_branch

    base_api_url = os.getenv("BASE_API_URL") or None
    core = Core(token=api_token, request_timeout=1200, base_api_url=base_api_url, allow_unverified=allow_unverified)
    no_change = True
    if ignore_commit_files:
        no_change = False
    elif is_repo and files is not None and len(files) > 0:
        log.info(files)
        no_change = core.match_supported_files(files)

    set_as_pending_head = False
    if default_branch:
        set_as_pending_head = True
    params = FullScanParams(
        repo=repo,
        branch=branch,
        commit_message=commit_message,
        commit_hash=commit_sha,
        pull_request=pr_number,
        committers=committer,
        make_default_branch=default_branch,
        set_as_pending_head=set_as_pending_head
    )
    diff = Diff()
    diff.id = "NO_DIFF_RAN"
    if scm is not None and scm.check_event_type() == "comment":
        log.info("Comment initiated flow")
        log.debug(f"Getting comments for Repo {scm.repository} for PR {scm.pr_number}")
        comments = scm.get_comments_for_pr(scm.repository, str(scm.pr_number))
        log.debug("Removing comment alerts")
        scm.remove_comment_alerts(comments)
    elif scm is not None and scm.check_event_type() != "comment":
        log.info("Push initiated flow")
        diff: Diff
        if no_change:
            log.info("No manifest files changes, skipping scan")
            # log.info("No dependency changes")
        elif scm.check_event_type() == "diff":
            diff = core.create_new_diff(target_path, params, workspace=target_path, no_change=no_change)
            log.info("Starting comment logic for PR/MR event")
            log.debug(f"Getting comments for Repo {scm.repository} for PR {scm.pr_number}")
            comments = scm.get_comments_for_pr(repo, str(pr_number))
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
            if len(diff.new_alerts) == 0 or disable_security_issue:
                if not update_old_security_comment:
                    new_security_comment = False
                    log.debug("No new alerts or security issue comment disabled")
                else:
                    log.debug("Updated security comment with no new alerts")
            if (len(diff.new_packages) == 0 and len(diff.removed_packages) == 0) or disable_overview:
                if not update_old_overview_comment:
                    new_overview_comment = False
                    log.debug("No new/removed packages or Dependency Overview comment disabled")
                else:
                    log.debug("Updated overview comment with no dependencies")
            log.debug(f"Adding comments for {scm_type}")
            scm.add_socket_comments(
                security_comment,
                overview_comment,
                comments,
                new_security_comment,
                new_overview_comment
            )
        else:
            log.info("Starting non-PR/MR flow")
            diff = core.create_new_diff(target_path, params, workspace=target_path, no_change=no_change)
        if enable_json:
            log.debug("Outputting JSON Results")
            output_console_json(diff, sbom_file)
        else:
            output_console_comments(diff, sbom_file)
    else:
        log.info("API Mode")
        diff: Diff
        diff = core.create_new_diff(target_path, params, workspace=target_path, no_change=no_change)
        if enable_json:
            output_console_json(diff, sbom_file)
        else:
            output_console_comments(diff, sbom_file)
    if diff is not None and license_mode:
        all_packages = {}
        for package_id in diff.packages:
            package: Package
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
        core.save_file(license_file, json.dumps(all_packages))


if __name__ == '__main__':
    cli()
