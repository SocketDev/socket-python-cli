import argparse
import json
from socketsecurity.core import Core, __version__
from socketsecurity.core.classes import FullScanParams, Diff, Package
from socketsecurity.core.messages import Messages
import os
import sys
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("socketcli")

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
    default='main',
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
    '--enable-json',
    help='Enable json output of results instead of table formatted',
    action='store_true',
    default=False
)


def output_console_comments(diff_report) -> None:
    console_security_comment = Messages.create_console_security_alert_table(diff_report)
    if len(diff_report.new_alerts) > 0:
        log.info("Security issues detected by Socket Security")
        log.info(console_security_comment)
        sys.exit(1)
    else:
        log.info("No New Security issues detected by Socket Security")


def output_console_json(diff_report) -> None:
    console_security_comment = Messages.create_security_comment_json(diff_report)
    print(json.dumps(console_security_comment))
    if len(diff_report.new_alerts) > 0:
        sys.exit(1)


def cli():
    try:
        main_code()
    except KeyboardInterrupt:
        log.info("Keyboard Interrupt detected, exiting")
        sys.exit(2)
    except Exception as error:
        log.error("Unexpected error when running the cli")
        log.error(error)
        sys.exit(3)


def main_code():
    arguments = parser.parse_args()
    debug = arguments.enable_debug
    if debug:
        logging.basicConfig(level=logging.DEBUG)
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
    license_file = f"{repo}"
    if branch is not None:
        license_file += f"_{branch}"
    license_file += ".json"
    api_token = os.getenv("SOCKET_SECURITY_API_KEY") or arguments.api_token
    if api_token is None:
        log.info("Unable to find Socket API Token")
        sys.exit(3)
    if repo is None:
        log.info("Repo name needs to be set")
        sys.exit(2)
    log.info(f"Starting Socket Security Scan version {__version__}")
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
    core = Core(token=api_token, request_timeout=6000, base_api_url=base_api_url)
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
    diff = None
    if scm is not None and scm.check_event_type() == "comment":
        log.info("Comment initiated flow")
        comments = scm.get_comments_for_pr(scm.repository, str(scm.pr_number))
        scm.remove_comment_alerts(comments)
    elif scm is not None and scm.check_event_type() != "comment":
        log.info("Push initiated flow")
        diff: Diff
        diff = core.create_new_diff(target_path, params, workspace=target_path)
        if scm.check_event_type() == "diff":
            comments = scm.get_comments_for_pr(repo, str(pr_number))
            diff.new_alerts = scm.remove_alerts(comments, diff.new_alerts)
            overview_comment = Messages.dependency_overview_template(diff)
            security_comment = Messages.security_comment_template(diff)
            new_security_comment = True
            new_overview_comment = True
            if len(diff.new_alerts) == 0:
                new_security_comment = False
            if len(diff.new_packages) == 0 and diff.removed_packages == 0:
                new_overview_comment = False
            scm.add_socket_comments(
                security_comment,
                overview_comment,
                comments,
                new_security_comment,
                new_overview_comment
            )
        if enable_json:
            output_console_json(diff)
        else:
            output_console_comments(diff)
    else:
        log.info("API Mode")
        diff: Diff
        diff = core.create_new_diff(target_path, params, workspace=target_path)
        if enable_json:
            output_console_json(diff)
        else:
            output_console_comments(diff)
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
    if diff is not None and sbom_file is not None:
        core.save_file(sbom_file, json.dumps(core.create_sbom_output(diff)))


if __name__ == '__main__':
    cli()
