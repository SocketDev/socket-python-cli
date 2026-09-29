import json
import os
import re
import signal
import subprocess
import time
import urllib.parse

from git import Repo

from socketsecurity.core import log

REMOTE_HEAD_TIMEOUT_SECONDS = 30
IS_WINDOWS = os.name == "nt"


class Git:
    repo: Repo
    path: str
    base_commit_sha: str | None

    def __init__(self, path: str, base_commit_sha: str | None = None):
        """
        Reads the repository state a scan is built from.

        Args:
            path: Path to the repository working tree
            base_commit_sha: Commit the comparison should start from. Supplied when
                the caller knows the range and no CI environment describes it, which
                is the only way changed-file detection can see commits behind HEAD.
        """
        initialization_start = time.perf_counter()
        self.path = path
        self.base_commit_sha = base_commit_sha
        self._fetched_ref_commits = {}
        self._default_branch_name: str | None = None
        self.ensure_safe_directory(path)
        self.repo = Repo(path)
        assert self.repo
        self.head = self.repo.head
        
        # Use CI environment SHA if available, otherwise fall back to current HEAD commit
        github_sha = os.getenv('GITHUB_SHA')
        gitlab_sha = os.getenv('CI_COMMIT_SHA')
        bitbucket_sha = os.getenv('BITBUCKET_COMMIT')
        buildkite_sha = os.getenv('BUILDKITE_COMMIT')
        ci_commits = (
            ("BUILDKITE_COMMIT", buildkite_sha),
            ("GITHUB_SHA", github_sha),
            ("CI_COMMIT_SHA", gitlab_sha),
            ("BITBUCKET_COMMIT", bitbucket_sha),
        )
        env_source, ci_sha = next(
            ((source, sha) for source, sha in ci_commits if sha),
            (None, None),
        )
        
        if ci_sha:
            try:
                self.commit = self.repo.commit(ci_sha)
                log.debug(f"Using commit from {env_source}: {ci_sha}")
            except Exception as error:
                log.debug(f"Failed to get commit from CI environment: {error}")
                # Use the actual current HEAD commit, not the head reference's commit
                self.commit = self.repo.commit('HEAD')
                log.debug(f"Using current HEAD commit: {self.commit.hexsha}")
        else:
            # Use the actual current HEAD commit, not the head reference's commit
            self.commit = self.repo.commit('HEAD')
            log.debug(f"Using current HEAD commit: {self.commit.hexsha}")
        
        log.debug(f"Final commit being used: {self.commit.hexsha}")
        log.debug(f"Commit author: {self.commit.author.name} <{self.commit.author.email}>")
        log.debug(f"Commit committer: {self.commit.committer.name} <{self.commit.committer.email}>")
        
        # Extract repository name from git remote, with fallback to default
        try:
            remote_url = self.repo.remotes.origin.url
            self.repo_name = remote_url.split('.git')[0].split('/')[-1]
            log.debug(f"Repository name detected from git remote: {self.repo_name}")
        except Exception as error:
            log.debug(f"Failed to get repository name from git remote: {error}")
            self.repo_name = "socket-default-repo"
            log.debug(f"Using default repository name: {self.repo_name}")
        
        # Branch detection with priority: CI Variables -> Git Properties -> Default
        # Note: CLI arguments are handled in socketcli.py and take highest priority
        
        # First, try CI environment variables (most accurate in CI environments)
        ci_branch = None
        
        # GitLab CI variables
        gitlab_branch = os.getenv('CI_COMMIT_BRANCH') or os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
        
        # GitHub Actions variables
        github_ref = os.getenv('GITHUB_REF')  # e.g., 'refs/heads/main'
        github_branch = None
        if github_ref and github_ref.startswith('refs/heads/'):
            github_branch = github_ref.replace('refs/heads/', '')
        
        # Bitbucket Pipelines variables
        bitbucket_branch = os.getenv('BITBUCKET_BRANCH')

        # Buildkite branch (the source branch for pull-request builds)
        buildkite_branch = os.getenv('BUILDKITE_BRANCH')
        
        # Prefer the native environment when Buildkite is driving the job. This
        # also avoids requiring Buildkite users to emulate GitHub Actions vars.
        ci_branch = buildkite_branch or gitlab_branch or github_branch or bitbucket_branch
        
        if ci_branch:
            self.branch = ci_branch
            if buildkite_branch:
                env_source = "Buildkite"
            elif gitlab_branch:
                env_source = "GitLab CI"
            elif github_branch:
                env_source = "GitHub Actions"
            else:
                env_source = "Bitbucket Pipelines"
            log.debug(f"Branch detected from {env_source}: {self.branch}")
        else:
            # Try to get branch name from git properties
            try:
                self.branch = urllib.parse.unquote(str(self.head.reference))
                log.debug(f"Branch detected from git reference: {self.branch}")
            except Exception as error:
                log.debug(f"Failed to get branch from git reference: {error}")
                
                # Fallback: try to detect branch from git commands (works in detached HEAD)
                git_detected_branch = None
                try:
                    # Try git name-rev first (most reliable for detached HEAD)
                    result = self.repo.git.name_rev('--name-only', 'HEAD')
                    if result and result != 'undefined':
                        # Strip name-rev suffix operators (~N, ^N, or combinations
                        # like master~3^2). These characters are forbidden in git
                        # ref names, so cutting at the first occurrence can never
                        # truncate a real branch name.
                        result = re.split(r'[~^]', result, maxsplit=1)[0]
                        # Clean up the result (remove any prefixes like 'remotes/origin/')
                        git_detected_branch = result.split('/')[-1]
                        log.debug(f"Branch detected from git name-rev: {git_detected_branch}")
                except Exception as git_error:
                    log.debug(f"git name-rev failed: {git_error}")
                    
                if not git_detected_branch:
                    try:
                        # Fallback: try git describe --all --exact-match
                        result = self.repo.git.describe('--all', '--exact-match', 'HEAD')
                        if result and result.startswith('heads/'):
                            git_detected_branch = result.replace('heads/', '')
                            log.debug(f"Branch detected from git describe: {git_detected_branch}")
                    except Exception as git_error:
                        log.debug(f"git describe failed: {git_error}")
                
                if git_detected_branch:
                    self.branch = git_detected_branch
                    log.debug(f"Branch detected from git commands: {self.branch}")
                else:
                    # Final fallback: use default branch name
                    self.branch = "socket-default-branch"
                    log.debug(f"Using default branch name: {self.branch}")
        self.author = self.commit.author
        self.commit_sha = self.commit.binsha
        self.commit_message = self.commit.message
        self.committer = self.commit.committer

        # Detect changed files in PR/MR context, using local refs first and
        # fetching only a required ref when the checkout does not contain it.
        changed_files_start = time.perf_counter()
        self.show_files = []
        detected = False
        detection_source = "single-commit"

        github_base_ref = os.getenv('GITHUB_BASE_REF')
        github_head_ref = os.getenv('GITHUB_HEAD_REF')
        github_event_name = os.getenv('GITHUB_EVENT_NAME')
        github_before_sha = os.getenv('GITHUB_EVENT_BEFORE')  # previous commit for push
        github_sha = os.getenv('GITHUB_SHA')  # current commit

        buildkite_pr = os.getenv('BUILDKITE_PULL_REQUEST')
        buildkite_base_ref = os.getenv('BUILDKITE_PULL_REQUEST_BASE_BRANCH')
        buildkite_head_ref = os.getenv('BUILDKITE_BRANCH')

        # An explicitly supplied base commit states the comparison range outright,
        # so it is honored before any inference from CI environment variables.
        if self.base_commit_sha:
            detected = self._detect_pull_request_changes(
                provider="explicit base commit",
                base_ref=self.base_commit_sha,
                head_ref=None,
                use_merge_base=False,
            )
            if detected:
                detection_source = "explicit-base-commit"
            else:
                log.warning(
                    f"Could not resolve base commit {self.base_commit_sha} in this "
                    "checkout, so changed-file detection falls back to the current "
                    "commit alone. A manifest changed earlier in the range will not "
                    "be seen, which can skip the comparison entirely. Deepen the "
                    "clone or fetch the base commit to compare the full range."
                )

        if not detected:
            if self._is_buildkite_pull_request(buildkite_pr) and buildkite_base_ref:
                detected = self._detect_pull_request_changes(
                    provider="Buildkite",
                    base_ref=buildkite_base_ref,
                    head_ref=buildkite_head_ref,
                )
                if detected:
                    detection_source = "buildkite-pr"
            elif github_event_name == 'pull_request' and github_base_ref:
                detected = self._detect_pull_request_changes(
                    provider="GitHub",
                    base_ref=github_base_ref,
                    head_ref=github_head_ref,
                )
                if detected:
                    detection_source = "github-pr"
            # Commits to default branch (push events)
            elif github_event_name == 'push' and github_before_sha and github_sha:
                try:
                    diff_files = self.repo.git.diff('--name-only', f'{github_before_sha}..{github_sha}')
                    self.show_files = diff_files.splitlines()
                    log.debug(f"Changed files detected via git diff (GitHub push): {self.show_files}")
                    detected = True
                    detection_source = "github-push"
                except Exception as error:
                    log.debug(f"Failed to get changed files via git diff (GitHub push): {error}")
            elif github_event_name == 'push':
                try:
                    self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
                    log.debug(f"Changed files detected via git show (GitHub push fallback): {self.show_files}")
                    detected = True
                    detection_source = "github-push-fallback"
                except Exception as error:
                    log.debug(f"Failed to get changed files via git show (GitHub push fallback): {error}")
        # GitLab CI Merge Request context
        if not detected:
            gitlab_target = os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')
            gitlab_source = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
            if gitlab_target and gitlab_source:
                detected = self._detect_pull_request_changes(
                    provider="GitLab",
                    base_ref=gitlab_target,
                    head_ref=gitlab_source,
                )
                if detected:
                    detection_source = "gitlab-mr"
        # Bitbucket Pipelines PR context
        if not detected:
            bitbucket_pr_id = os.getenv('BITBUCKET_PR_ID')
            bitbucket_source = os.getenv('BITBUCKET_BRANCH')
            bitbucket_dest = os.getenv('BITBUCKET_PR_DESTINATION_BRANCH')
            # BITBUCKET_BRANCH is the source branch in PR builds
            if bitbucket_pr_id and bitbucket_source and bitbucket_dest:
                detected = self._detect_pull_request_changes(
                    provider="Bitbucket",
                    base_ref=bitbucket_dest,
                    head_ref=bitbucket_source,
                )
                if detected:
                    detection_source = "bitbucket-pr"
        # Fallback to git show for single commit
        if not detected:
            # Check if this is a merge commit first
            if self._is_merge_commit():
                # For merge commits, use git diff with parent
                if self._detect_merge_commit_changes():
                    detected = True
                else:
                    # Fallback to git show if merge detection fails
                    self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
                    log.debug(f"Changed files detected via git show (merge commit fallback): {self.show_files}")
                    detected = True
                    detection_source = "merge-commit-fallback"
                if detected and detection_source == "single-commit":
                    detection_source = "merge-diff"
            else:
                # Regular single commit
                self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
                log.debug(f"Changed files detected via git show: {self.show_files}")
                detected = True
                detection_source = "single-commit"
        self.changed_files = []
        for item in self.show_files:
            if item != "":
                # Use relative path for glob matching
                self.changed_files.append(item)

        log.info(
            "Changed-file detection completed in "
            f"{time.perf_counter() - changed_files_start:.2f}s: "
            f"source={detection_source}, files={len(self.changed_files)}"
        )
        
        # Determine if this commit is on the default branch
        # This considers both GitHub Actions detached HEAD and regular branch situations
        self.is_default_branch = self._is_commit_and_branch_default()
        log.info(
            "Git initialization completed in "
            f"{time.perf_counter() - initialization_start:.2f}s"
        )

    @staticmethod
    def _is_buildkite_pull_request(pull_request: str | None) -> bool:
        return bool(pull_request and pull_request.casefold() != "false")

    def _resolve_ref(self, ref: str | None) -> str | None:
        """Resolve a branch, tag, or SHA without accessing the network."""
        if not ref:
            return None
        if ref in self._fetched_ref_commits:
            return self._fetched_ref_commits[ref]

        candidates = [ref]
        if not ref.startswith("refs/"):
            candidates = [f"origin/{ref}", ref]
        for candidate in candidates:
            try:
                return self.repo.commit(candidate).hexsha
            except Exception:
                continue
        return None

    def _fetch_ref(self, ref: str, reason: str) -> str | None:
        """Fetch one required ref and return its commit without broadening scope."""
        if ref in self._fetched_ref_commits:
            return self._fetched_ref_commits[ref]

        fetch_start = time.perf_counter()
        try:
            self.repo.git.fetch("origin", ref)
            commit_sha = self.repo.commit("FETCH_HEAD").hexsha
            self._fetched_ref_commits[ref] = commit_sha
            log.info(
                "Git fetch completed in "
                f"{time.perf_counter() - fetch_start:.2f}s: "
                f"remote=origin, ref={ref}, reason={reason}"
            )
            return commit_sha
        except Exception as error:
            log.info(
                "Git fetch failed in "
                f"{time.perf_counter() - fetch_start:.2f}s: "
                f"remote=origin, ref={ref}, reason={reason}"
            )
            log.debug(f"Targeted fetch failed for {ref}: {error}")
            return None

    def _detect_pull_request_changes(
            self,
            provider: str,
            base_ref: str,
            head_ref: str | None,
            use_merge_base: bool = True,
    ) -> bool:
        """Detect a base-to-head range locally, fetching only refs needed to complete it."""
        base_commit = self._resolve_ref(base_ref)
        if base_commit is None:
            base_commit = self._fetch_ref(base_ref, f"{provider} pull-request base ref missing")
        if base_commit is None:
            log.debug(f"Unable to resolve {provider} pull-request base ref: {base_ref}")
            return False

        head_commit = self.commit.hexsha
        range_separator = "..." if use_merge_base else ".."
        diff_range = f"{base_commit}{range_separator}{head_commit}"
        try:
            diff_files = self.repo.git.diff("--name-only", diff_range)
            self.show_files = diff_files.splitlines()
            log.debug(
                f"Changed files detected via local git diff ({provider}): {self.show_files}"
            )
            return True
        except Exception as local_error:
            log.debug(f"Local {provider} pull-request diff failed: {local_error}")

        # A shallow checkout can contain both tips but not their merge base. In
        # that case refresh only the two relevant branch histories and retry.
        base_commit = self._fetch_ref(
            base_ref,
            f"{provider} pull-request history incomplete",
        ) or base_commit
        if head_ref:
            self._fetch_ref(
                head_ref,
                f"{provider} pull-request history incomplete",
            )

        try:
            diff_files = self.repo.git.diff(
                "--name-only",
                f"{base_commit}{range_separator}{head_commit}",
            )
            self.show_files = diff_files.splitlines()
            log.debug(
                f"Changed files detected after targeted fetch ({provider}): {self.show_files}"
            )
            return True
        except Exception as retry_error:
            log.debug(f"Targeted {provider} pull-request diff failed: {retry_error}")
            return False

    def _is_commit_and_branch_default(self) -> bool:
        """
        Check if both the commit is on the default branch AND we're processing the default branch.
        This handles GitHub Actions detached HEAD state properly.
        
        Returns:
            True if commit is on default branch and we're processing the default branch
        """
        try:
            github_ref = os.getenv('GITHUB_REF')  # e.g., 'refs/heads/main' or 'refs/pull/123/merge'
            gitlab_branch = os.getenv('CI_COMMIT_BRANCH')
            gitlab_mr_branch = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
            bitbucket_branch = os.getenv('BITBUCKET_BRANCH')
            bitbucket_pr = os.getenv('BITBUCKET_PR_ID')
            buildkite_branch = os.getenv('BUILDKITE_BRANCH')
            buildkite_pr = os.getenv('BUILDKITE_PULL_REQUEST')

            # PR and non-branch builds cannot become the default branch head.
            # Decide that locally before default-branch lookup contacts origin.
            if buildkite_branch:
                if self._is_buildkite_pull_request(buildkite_pr):
                    log.debug(
                        f"Processing Buildkite pull request from branch: {buildkite_branch}, "
                        "not default branch"
                    )
                    return False
            elif github_ref:
                if github_ref.startswith('refs/pull/'):
                    log.debug("Processing a pull request, not default branch")
                    return False
                if not github_ref.startswith('refs/heads/'):
                    log.debug(f"Non-branch ref: {github_ref}, not default branch")
                    return False
            elif gitlab_branch or gitlab_mr_branch:
                if gitlab_mr_branch:
                    log.debug(f"Processing GitLab MR from branch: {gitlab_mr_branch}, not default branch")
                    return False
            elif bitbucket_branch and bitbucket_pr:
                log.debug(f"Processing Bitbucket pull request from branch: {bitbucket_branch}, not default branch")
                return False

            if not self.is_commit_on_default_branch():
                log.debug("Commit is not on default branch")
                return False

            # Handle Buildkite before GitHub because some Buildkite pipelines
            # intentionally provide GitHub-compatible environment variables.
            if buildkite_branch:
                default_branch_name = self.get_default_branch_name()
                is_default = buildkite_branch == default_branch_name
                log.debug(
                    f"Buildkite branch: {buildkite_branch}, Default: {default_branch_name}, "
                    f"Is default: {is_default}"
                )
                return is_default

            # Handle GitHub Actions
            elif github_ref:
                log.debug(f"GitHub ref: {github_ref}")
                branch_from_ref = github_ref.removeprefix('refs/heads/')
                default_branch_name = self.get_default_branch_name()
                is_default = branch_from_ref == default_branch_name
                log.debug(f"Branch from GITHUB_REF: {branch_from_ref}, Default: {default_branch_name}, Is default: {is_default}")
                return is_default
            
            # Handle GitLab CI
            elif gitlab_branch or gitlab_mr_branch:
                current_branch = gitlab_mr_branch or gitlab_branch
                default_branch_name = self.get_default_branch_name()
                is_default = current_branch == default_branch_name
                log.debug(f"GitLab branch: {current_branch}, Default: {default_branch_name}, Is default: {is_default}")
                return is_default
            
            # Handle Bitbucket Pipelines
            elif bitbucket_branch:
                default_branch_name = self.get_default_branch_name()
                is_default = bitbucket_branch == default_branch_name
                log.debug(f"Bitbucket branch: {bitbucket_branch}, Default: {default_branch_name}, Is default: {is_default}")
                return is_default
            else:
                # Not in GitHub Actions, use local development logic
                # For local development, we consider it "default branch" if:
                # 1. Currently on the default branch, OR
                # 2. The commit is reachable from the default branch (part of default branch history)
                
                is_on_default = self.is_on_default_branch()
                if is_on_default:
                    log.debug("Currently on default branch locally")
                    return True
                
                # Even if on feature branch, if commit is on default branch, consider it default
                # This handles cases where feature branch was created from or merged to default
                is_commit_default = self.is_commit_on_default_branch()
                log.debug(f"Not on default branch locally, but commit is on default branch: {is_commit_default}")
                return is_commit_default
                
        except Exception as error:
            log.debug(f"Error determining if commit and branch are default: {error}")
            return False

    @property
    def commit_str(self) -> str:
        """Return commit SHA as a string"""
        return self.commit.hexsha
    
    def get_formatted_committer(self) -> str:
        """
        Get the committer in the preferred order:
        1. CLI --committers (handled in socketcli.py)
        2. CI/CD SCM username (GitHub/GitLab/BitBucket environment variables)
        3. Git username (extracted from email patterns like GitHub noreply)
        4. Git email address
        5. Git author name (fallback)
        
        Returns:
            Formatted committer string
        """
        # Check for CI/CD environment usernames first
        # GitHub Actions
        github_actor = os.getenv('GITHUB_ACTOR')
        if github_actor:
            log.debug(f"Using GitHub actor as committer: {github_actor}")
            return github_actor
        
        # GitLab CI
        gitlab_user_login = os.getenv('GITLAB_USER_LOGIN')
        if gitlab_user_login:
            log.debug(f"Using GitLab user login as committer: {gitlab_user_login}")
            return gitlab_user_login
        
        # Bitbucket Pipelines
        bitbucket_step_triggerer_uuid = os.getenv('BITBUCKET_STEP_TRIGGERER_UUID')
        if bitbucket_step_triggerer_uuid:
            log.debug(f"Using Bitbucket step triggerer as committer: {bitbucket_step_triggerer_uuid}")
            return bitbucket_step_triggerer_uuid
        
        # Fall back to commit author/committer details
        # Priority 3: Try to extract git username from email patterns first
        if self.author and self.author.email and self.author.email.strip():
            email = self.author.email.strip()
            
            # If it's a GitHub noreply email, try to extract username
            if email.endswith('@users.noreply.github.com'):
                # Pattern: number+username@users.noreply.github.com
                email_parts = email.split('@')[0]
                if '+' in email_parts:
                    username = email_parts.split('+')[1]
                    log.debug(f"Extracted GitHub username from noreply email: {username}")
                    return username
        
        # Priority 4: Use email if available
        if self.author and self.author.email and self.author.email.strip():
            email = self.author.email.strip()
            log.debug(f"Using commit author email as committer: {email}")
            return email
        
        # Priority 5: Fall back to author name as last resort
        if self.author and self.author.name and self.author.name.strip():
            name = self.author.name.strip()
            log.debug(f"Using commit author name as fallback committer: {name}")
            return name
        
        # Ultimate fallback
        log.debug("Using fallback committer: unknown")
        return "unknown"
    
    def _is_merge_commit(self) -> bool:
        """
        Check if the current commit is a merge commit.
        
        Returns:
            True if this is a merge commit (has multiple parents), False otherwise
        """
        try:
            # A merge commit has multiple parents
            is_merge = len(self.commit.parents) > 1
            log.debug(f"Commit {self.commit.hexsha[:8]} has {len(self.commit.parents)} parents, is_merge: {is_merge}")
            return is_merge
        except Exception as error:
            log.debug(f"Error checking if commit is merge commit: {error}")
            return False
    
    def _detect_merge_commit_changes(self) -> bool:
        """
        Detect changed files in a merge commit using git diff with parent.
        
        This method handles the case where git show --name-only doesn't work
        for merge commits (expected Git behavior).
        
        Returns:
            True if detection was successful, False otherwise
        """
        try:
            if not self._is_merge_commit():
                log.debug("Not a merge commit, skipping merge commit detection")
                return False
            
            # For merge commits, we need to diff against a parent
            # We'll use the first parent (typically the target branch)
            if not self.commit.parents:
                log.debug("Merge commit has no parents - cannot perform merge-aware diff")
                return False
            
            parent_commit = self.commit.parents[0]
            
            # Verify parent commit is accessible
            try:
                parent_sha = parent_commit.hexsha
                # Quick validation that parent exists
                self.repo.commit(parent_sha)
            except Exception as parent_error:
                log.error(f"Cannot resolve parent commit {parent_sha}: {parent_error}")
                return False
            
            # Use git diff to show changes from parent to merge commit
            diff_range = f'{parent_sha}..{self.commit.hexsha}'
            log.debug(f"Attempting merge commit diff: git diff --name-only {diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', diff_range)
            self.show_files = diff_files.splitlines()
            
            log.debug(f"Changed files detected via git diff (merge commit): {self.show_files}")
            log.info(f"Changed file detection: method=merge-diff, source=merge-commit-fallback, files={len(self.show_files)}")
            return True
            
        except Exception as error:
            log.debug(f"Failed to detect merge commit changes: {error}")
            return False
    
    def get_default_branch_name(self) -> str:
        """
        Get the default branch name from the remote origin.
        
        Returns:
            Default branch name (e.g., 'main', 'master')
        """
        if self._default_branch_name is None:
            self._default_branch_name = self._detect_default_branch_name()
        return self._default_branch_name

    def _detect_default_branch_name(self) -> str:
        for variable in ('CI_DEFAULT_BRANCH', 'BUILDKITE_PIPELINE_DEFAULT_BRANCH'):
            default_branch = os.getenv(variable)
            if default_branch:
                log.debug(f"Default branch detected from {variable}: {default_branch}")
                return default_branch

        try:
            default_branch = self.repo.remotes.origin.refs.HEAD.reference.remote_head
            log.debug(f"Default branch detected from origin/HEAD: {default_branch}")
            return default_branch
        except Exception as error:
            log.debug(f"Could not determine default branch from origin/HEAD: {error}")

        # CI checkouts such as actions/checkout fetch a single branch and leave no origin/HEAD.
        default_branch = (
            self._default_branch_from_github_event()
            or self._default_branch_from_remote()
        )
        if default_branch:
            return default_branch

        try:
            remote_refs = {str(ref) for ref in self.repo.remotes.origin.refs}
        except Exception:
            remote_refs = set()
        for branch_name in ['main', 'master']:
            if f'origin/{branch_name}' in remote_refs:
                log.debug(f"Using fallback default branch: {branch_name}")
                return branch_name

        log.debug("Using final fallback default branch: main")
        return 'main'

    @staticmethod
    def _default_branch_from_github_event() -> str | None:
        event_path = os.getenv('GITHUB_EVENT_PATH')
        if not event_path:
            return None
        try:
            with open(event_path, encoding="utf-8") as event_file:
                default_branch = json.load(event_file).get("repository", {}).get("default_branch")
        except Exception as error:
            log.debug(f"Could not read default branch from GitHub event payload: {error}")
            return None
        if default_branch:
            log.debug(f"Default branch detected from GitHub event payload: {default_branch}")
        return default_branch or None

    def _default_branch_from_remote(self) -> str | None:
        # A new session lets a timeout also kill the remote helpers, which otherwise
        # hold stdout open and keep communicate() blocked. Windows ignores it.
        try:
            process = subprocess.Popen(
                ["git", "ls-remote", "--symref", "origin", "HEAD"],
                cwd=self.repo.working_dir,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
        except Exception as error:
            log.debug(f"Could not query origin for its default branch: {error}")
            return None
        try:
            output, _ = process.communicate(timeout=REMOTE_HEAD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self._kill_process_tree(process)
            log.debug(
                f"Querying origin for its default branch timed out after "
                f"{REMOTE_HEAD_TIMEOUT_SECONDS}s"
            )
            return None
        if process.returncode != 0:
            log.debug(f"Querying origin for its default branch exited with {process.returncode}")
            return None
        for line in output.splitlines():
            match = re.match(r"ref: refs/heads/(\S+)\tHEAD$", line)
            if match:
                log.debug(f"Default branch detected from origin: {match.group(1)}")
                return match.group(1)
        return None

    @staticmethod
    def _kill_process_tree(process: subprocess.Popen) -> None:
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except Exception as error:
            log.debug(f"Failed to stop git ls-remote process tree: {error}")
            process.kill()
        if process.stdout:
            process.stdout.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log.debug("git ls-remote did not exit after being killed")
    
    def is_commit_on_default_branch(self) -> bool:
        """
        Check if the current commit is reachable from the default branch.
        
        Returns:
            True if current commit is on the default branch, False otherwise
        """
        try:
            default_branch = self.get_default_branch_name()
            
            # Get the default branch's HEAD commit
            try:
                # Try remote branch first
                default_branch_ref = self.repo.remotes.origin.refs[default_branch]
                default_branch_commit = default_branch_ref.commit
            except Exception:
                # Fallback to local branch
                try:
                    default_branch_ref = self.repo.heads[default_branch] 
                    default_branch_commit = default_branch_ref.commit
                except Exception:
                    log.debug(f"Could not find default branch '{default_branch}' locally or remotely")
                    return False
            
            # Check if current commit is the same as default branch HEAD
            if self.commit.hexsha == default_branch_commit.hexsha:
                log.debug("Current commit is the HEAD of the default branch")
                return True
            
            # Check if current commit is an ancestor of the default branch HEAD
            # This means the commit is reachable from the default branch
            is_ancestor = self.repo.is_ancestor(self.commit, default_branch_commit)
            log.debug(f"Current commit is ancestor of default branch: {is_ancestor}")
            return is_ancestor
            
        except Exception as error:
            log.debug(f"Error checking if commit is on default branch: {error}")
            return False
    
    def is_on_default_branch(self) -> bool:
        """
        Check if we're currently on the default branch (not just if commit is reachable).
        
        Returns:
            True if currently on the default branch, False otherwise
        """
        try:
            # If we're in detached HEAD state, we're not "on" any branch
            if self.repo.head.is_detached:
                log.debug("In detached HEAD state, not on any branch")
                return False
            
            current_branch_name = self.repo.active_branch.name
            default_branch_name = self.get_default_branch_name()
            
            is_default = current_branch_name == default_branch_name
            log.debug(f"Current branch: {current_branch_name}, Default branch: {default_branch_name}, Is default: {is_default}")
            return is_default
            
        except Exception as error:
            log.debug(f"Error checking if on default branch: {error}")
            return False

    @staticmethod
    def ensure_safe_directory(path: str) -> None:
        # Ensure the repo is marked as safe for git (prevents SHA empty/dubious ownership errors)
        try :
            import subprocess
            abs_path = os.path.abspath(path)
            # Get all safe directories
            result = subprocess.run([
                "git", "config", "--global", "--get-all", "safe.directory"
            ], capture_output=True, text=True)
            safe_dirs = result.stdout.splitlines() if result.returncode == 0 else []
            if abs_path not in safe_dirs:
                subprocess.run([
                    "git", "config", "--global", "--add", "safe.directory", abs_path
                ], check=True)
                log.debug(f"Added {abs_path} to git safe.directory config.")
            else:
                log.debug(f"{abs_path} already present in git safe.directory config.")
        except Exception as safe_error:
            log.debug(f"Failed to set safe.directory for git: {safe_error}")
