import urllib.parse
import os

from git import Repo

from socketsecurity.core import log


class Git:
    """
    Git interface for detecting changed files in various CI environments.
    
    DETECTION STRATEGY:
    This class implements a 3-tier detection strategy to identify changed files:
    
    1. MR/PR Detection (CI-provided ranges) - PREFERRED
       - GitLab MR: git diff origin/<target>...origin/<source> (GOLD PATH)
       - GitHub PR: git diff origin/<base>...origin/<head>
       - Bitbucket PR: git diff origin/<dest>...origin/<source>
    
    2. Push Detection (commit ranges)
       - GitHub Push: git diff <before>..<after>
    
    3. Fallback Detection (local analysis) - LAST RESORT
       - Merge commits: git diff <parent^1>..<commit>
       - Single commits: git show --name-only <commit>
    
    KNOWN LIMITATIONS:
    - git show --name-only <merge-commit> does NOT list filenames (expected Git behavior)
    - Squash merges: Detected by commit message keywords, may miss some cases
    - Octopus merges: Uses first-parent diff only, may not show all changes
    - First-parent assumption: Assumes main branch is first parent (usually true)
    
    LAZY LOADING:
    Changed file detection is lazy-loaded via @property decorators to avoid
    unnecessary Git operations during object initialization.
    """
    repo: Repo
    path: str

    def __init__(self, path: str):
        self.path = path
        self.ensure_safe_directory(path)
        self.repo = Repo(path)
        assert self.repo
        self.head = self.repo.head

        # Always fetch all remote refs to ensure branches exist for diffing
        try:
            self.repo.git.fetch('--all')
            log.debug("Fetched all remote refs for diffing.")
        except Exception as fetch_error:
            log.debug(f"Failed to fetch all remote refs: {fetch_error}")
        
        # Use CI environment SHA if available, otherwise fall back to current HEAD commit
        github_sha = os.getenv('GITHUB_SHA')
        github_event_name = os.getenv('GITHUB_EVENT_NAME')
        gitlab_sha = os.getenv('CI_COMMIT_SHA')
        bitbucket_sha = os.getenv('BITBUCKET_COMMIT')
        
        # For GitHub PR events, ignore GITHUB_SHA (virtual merge commit) and use HEAD
        if github_event_name == 'pull_request':
            ci_sha = gitlab_sha or bitbucket_sha  # Skip github_sha
            log.debug("GitHub PR event detected - ignoring GITHUB_SHA (virtual merge commit)")
        else:
            ci_sha = github_sha or gitlab_sha or bitbucket_sha
        
        if ci_sha:
            try:
                self.commit = self.repo.commit(ci_sha)
                if ci_sha == github_sha and github_event_name != 'pull_request':
                    env_source = "GITHUB_SHA"
                elif ci_sha == gitlab_sha:
                    env_source = "CI_COMMIT_SHA"
                elif ci_sha == bitbucket_sha:
                    env_source = "BITBUCKET_COMMIT"
                else:
                    env_source = "UNKNOWN_CI_SOURCE"
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
        github_ref = os.getenv('GITHUB_REF')  # e.g., 'refs/heads/main' or 'refs/pull/123/merge'
        github_head_ref = os.getenv('GITHUB_HEAD_REF')  # PR source branch name
        github_branch = None
        
        # For PR events, use GITHUB_HEAD_REF (actual branch name), not GITHUB_REF (virtual merge ref)
        if github_event_name == 'pull_request' and github_head_ref:
            github_branch = github_head_ref
            log.debug(f"GitHub PR event - using GITHUB_HEAD_REF: {github_branch}")
        elif github_ref and github_ref.startswith('refs/heads/'):
            github_branch = github_ref.replace('refs/heads/', '')
            log.debug(f"GitHub push event - using GITHUB_REF: {github_branch}")
        elif github_ref and github_ref.startswith('refs/pull/') and github_ref.endswith('/merge'):
            # Fallback: if we somehow miss the PR detection above, don't use the virtual merge ref
            log.debug(f"GitHub virtual merge ref detected, skipping: {github_ref}")
            github_branch = None
        
        # Bitbucket Pipelines variables
        bitbucket_branch = os.getenv('BITBUCKET_BRANCH')
        
        # Select CI branch with priority: GitLab -> GitHub -> Bitbucket
        ci_branch = gitlab_branch or github_branch or bitbucket_branch
        
        if ci_branch:
            self.branch = ci_branch
            if gitlab_branch:
                env_source = "GitLab CI"
            elif github_branch:
                env_source = "GitHub Actions"
            else:
                env_source = "Bitbucket Pipelines"
            log.debug(f"Branch detected from {env_source}: {self.branch}")
        else:
            # Try to get branch name from git properties
            try:
                self.branch = self.head.reference
                urllib.parse.unquote(str(self.branch))
                log.debug(f"Branch detected from git reference: {self.branch}")
            except Exception as error:
                log.debug(f"Failed to get branch from git reference: {error}")
                
                # Fallback: try to detect branch from git commands (works in detached HEAD)
                git_detected_branch = None
                try:
                    # Try git name-rev first (most reliable for detached HEAD)
                    result = self.repo.git.name_rev('--name-only', 'HEAD')
                    if result and result != 'undefined':
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
        # Changed file discovery is now lazy - computed only when needed
        self._show_files = None
        self._changed_files = None
        self._detection_method = None
        
        # Determine if this commit is on the default branch
        # This considers both GitHub Actions detached HEAD and regular branch situations
        self.is_default_branch = self._is_commit_and_branch_default()

    def _is_commit_and_branch_default(self) -> bool:
        """
        Check if both the commit is on the default branch AND we're processing the default branch.
        This handles GitHub Actions detached HEAD state properly.
        
        Returns:
            True if commit is on default branch and we're processing the default branch
        """
        try:
            # First check if the commit is reachable from the default branch
            if not self.is_commit_on_default_branch():
                log.debug("Commit is not on default branch")
                return False
            
            # Check if we're processing the default branch via CI environment variables
            github_ref = os.getenv('GITHUB_REF')  # e.g., 'refs/heads/main' or 'refs/pull/123/merge'
            gitlab_branch = os.getenv('CI_COMMIT_BRANCH')
            gitlab_mr_branch = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
            gitlab_default_branch = os.getenv('CI_DEFAULT_BRANCH', '')
            bitbucket_branch = os.getenv('BITBUCKET_BRANCH')
            
            # Handle GitHub Actions
            if github_ref:
                log.debug(f"GitHub ref: {github_ref}")
                
                # Handle pull requests - they're not on the default branch
                if github_ref.startswith('refs/pull/'):
                    log.debug("Processing a pull request, not default branch")
                    return False
                
                # Handle regular branch pushes
                if github_ref.startswith('refs/heads/'):
                    branch_from_ref = github_ref.replace('refs/heads/', '')
                    default_branch_name = self.get_default_branch_name()
                    is_default = branch_from_ref == default_branch_name
                    log.debug(f"Branch from GITHUB_REF: {branch_from_ref}, Default: {default_branch_name}, Is default: {is_default}")
                    return is_default
                
                # Handle tags or other refs - not default branch
                log.debug(f"Non-branch ref: {github_ref}, not default branch")
                return False
            
            # Handle GitLab CI
            elif gitlab_branch or gitlab_mr_branch:
                # If this is a merge request, use the source branch
                current_branch = gitlab_mr_branch or gitlab_branch
                default_branch_name = gitlab_default_branch or self.get_default_branch_name()
                
                # For merge requests, they're typically not considered "default branch"
                if gitlab_mr_branch:
                    log.debug(f"Processing GitLab MR from branch: {gitlab_mr_branch}, not default branch")
                    return False
                
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

    @property
    def show_files(self):
        """Lazy computation of changed files"""
        if self._show_files is None:
            self._detect_changed_files()
        return self._show_files

    @property
    def changed_files(self):
        """Lazy computation of changed files (filtered)"""
        if self._changed_files is None:
            self._detect_changed_files()
        return self._changed_files

    def _detect_changed_files(self):
        """
        Detect changed files using appropriate method based on environment.
        
        This method orchestrates the detection process and handles errors gracefully.
        It calls the internal implementation and sets up error handling for lazy loading.
        """
        self._show_files = []
        detected = False
        
        try:
            self._detect_changed_files_internal()
        except Exception as error:
            # Log clear failure message for lazy loading
            log.error(f"Changed file detection failed: {error}")
            log.error(f"Detection method: {self._detection_method or 'none'}")
            log.error(f"Files found: {len(self._show_files)}")
            # Set empty defaults to prevent repeated failures
            self._show_files = []
            self._changed_files = []
            self._detection_method = "error"
            raise

    def _detect_changed_files_internal(self):
        """
        Internal implementation of changed file detection.
        
        This method implements the detection logic in 3 cohesive groups:
        1. MR/PR Detection: GitLab MR, GitHub PR, Bitbucket PR (CI-provided ranges)
        2. Push Detection: GitHub push events (commit ranges)
        3. Fallback Detection: Merge-aware (parent diff) and single-commit (git show)
        """
        self._show_files = []
        detected = False

        # GROUP 1: MR/PR Detection (CI-provided branch ranges)
        detected = self._detect_mr_pr_contexts() or detected
        
        # GROUP 2: Push Detection (commit ranges)  
        detected = self._detect_push_contexts() or detected
        
        # GROUP 3: Fallback Detection (local analysis)
        if not detected:
            self._detect_fallback_contexts()
        
        # Filter out empty strings and set changed_files
        self._filter_and_set_changed_files()
        
        # Log final results
        self._log_detection_results()

    def _detect_mr_pr_contexts(self) -> bool:
        """
        Detect changes using MR/PR context from CI environments.
        
        Priority: GitLab MR (GOLD PATH) > GitHub PR > Bitbucket PR
        All use git diff with CI-provided branch ranges.
        
        Returns:
            True if detection was successful, False otherwise
        """
        # GitLab CI Merge Request context (GOLD PATH)
        if self._detect_gitlab_mr_context():
            return True
            
        # GitHub Actions PR context
        if self._detect_github_pr_context():
            return True
            
        # Bitbucket Pipelines PR context
        if self._detect_bitbucket_pr_context():
            return True
            
        return False

    def _detect_push_contexts(self) -> bool:
        """
        Detect changes using push context from CI environments.
        
        Currently only GitHub Actions push events with before/after SHAs.
        Uses git diff with commit ranges.
        
        Returns:
            True if detection was successful, False otherwise
        """
        return self._detect_github_push_context()

    def _detect_fallback_contexts(self) -> None:
        """
        Detect changes using local Git analysis as fallback.
        
        Priority: Merge-aware (parent diff) > Single-commit (git show)
        Used when CI environment variables are not available.
        """
        # Try merge-aware fallback for merge commits
        if not self._detect_merge_commit_fallback():
            # Final fallback to git show for single commits
            self._detect_single_commit_fallback()

    def _detect_github_pr_context(self) -> bool:
        """
        Detect changed files in GitHub Actions PR context.
        
        Returns:
            True if detection was successful, False otherwise
        """
        github_event_name = os.getenv('GITHUB_EVENT_NAME')
        github_base_ref = os.getenv('GITHUB_BASE_REF')
        github_head_ref = os.getenv('GITHUB_HEAD_REF')
        
        if github_event_name != 'pull_request' or not github_base_ref or not github_head_ref:
            return False
            
        try:
            # Fetch both branches individually
            self.repo.git.fetch('origin', github_base_ref)
            self.repo.git.fetch('origin', github_head_ref)
            
            # Try remote diff first
            if self._try_github_remote_diff(github_base_ref, github_head_ref):
                return True
                
            # Try local branch diff as fallback
            if self._try_github_local_diff(github_base_ref, github_head_ref):
                return True
                
        except Exception as error:
            log.debug(f"Failed to fetch branches or diff for GitHub PR: {error}")
        
        return False

    def _try_github_remote_diff(self, base_ref: str, head_ref: str) -> bool:
        """Try to detect changes using remote branch diff."""
        try:
            diff_range = f"origin/{base_ref}...origin/{head_ref}"
            log.debug(f"Attempting GitHub PR remote diff: git diff --name-only {diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', diff_range)
            self._show_files = diff_files.splitlines()
            self._detection_method = "mr-diff"
            
            log.debug(f"Changed files detected via git diff (GitHub PR remote): {self._show_files}")
            log.info(f"Changed file detection: method=mr-diff, source=github-pr-remote, files={len(self._show_files)}")
            return True
            
        except Exception as remote_error:
            log.debug(f"Remote diff failed: {remote_error}")
            return False

    def _try_github_local_diff(self, base_ref: str, head_ref: str) -> bool:
        """Try to detect changes using local branch diff."""
        try:
            local_diff_range = f"{base_ref}...{head_ref}"
            log.debug(f"Attempting GitHub PR local diff: git diff --name-only {local_diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', local_diff_range)
            self._show_files = diff_files.splitlines()
            self._detection_method = "mr-diff"
            
            log.debug(f"Changed files detected via git diff (GitHub PR local): {self._show_files}")
            log.info(f"Changed file detection: method=mr-diff, source=github-pr-local, files={len(self._show_files)}")
            return True
            
        except Exception as local_error:
            log.debug(f"Local diff failed: {local_error}")
            return False

    def _detect_github_push_context(self) -> bool:
        """
        Detect changed files in GitHub Actions push context.
        
        Returns:
            True if detection was successful, False otherwise
        """
        github_event_name = os.getenv('GITHUB_EVENT_NAME')
        github_before_sha = os.getenv('GITHUB_EVENT_BEFORE')
        github_sha = os.getenv('GITHUB_SHA')
        
        if github_event_name != 'push' or not github_before_sha or not github_sha:
            return False
            
        try:
            diff_range = f'{github_before_sha}..{github_sha}'
            log.debug(f"Attempting GitHub push diff: git diff --name-only {diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', diff_range)
            self._show_files = diff_files.splitlines()
            self._detection_method = "push-diff"
            
            log.debug(f"Changed files detected via git diff (GitHub push): {self._show_files}")
            log.info(f"Changed file detection: method=push-diff, source=github-push, files={len(self._show_files)}")
            return True
            
        except Exception as error:
            log.debug(f"Failed to get changed files via git diff (GitHub push): {error}")
            return False

    def _detect_gitlab_mr_context(self) -> bool:
        """
        Detect changed files in GitLab CI Merge Request context (GOLD PATH).
        
        Returns:
            True if detection was successful, False otherwise
        """
        gitlab_target = os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')
        gitlab_source = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
        
        if not gitlab_target or not gitlab_source:
            return False
            
        try:
            self.repo.git.fetch('origin', gitlab_target, gitlab_source)
            diff_range = f"origin/{gitlab_target}...origin/{gitlab_source}"
            log.debug(f"Attempting GitLab MR diff (GOLD PATH): git diff --name-only {diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', diff_range)
            self._show_files = diff_files.splitlines()
            self._detection_method = "mr-diff"
            
            log.debug(f"Changed files detected via git diff (GitLab): {self._show_files}")
            log.info(f"Changed file detection: method=mr-diff, source=gitlab-mr-gold-path, files={len(self._show_files)}")
            return True
            
        except Exception as error:
            log.debug(f"Failed to get changed files via git diff (GitLab): {error}")
            return False

    def _detect_bitbucket_pr_context(self) -> bool:
        """
        Detect changed files in Bitbucket Pipelines PR context.
        
        Returns:
            True if detection was successful, False otherwise
        """
        bitbucket_source = os.getenv('BITBUCKET_BRANCH')
        bitbucket_target = os.getenv('BITBUCKET_PR_DESTINATION_BRANCH')
        
        if not bitbucket_source or not bitbucket_target:
            return False
            
        try:
            self.repo.git.fetch('origin', bitbucket_target, bitbucket_source)
            diff_range = f"origin/{bitbucket_target}...origin/{bitbucket_source}"
            log.debug(f"Attempting Bitbucket PR diff: git diff --name-only {diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', diff_range)
            self._show_files = diff_files.splitlines()
            self._detection_method = "mr-diff"
            
            log.debug(f"Changed files detected via git diff (Bitbucket): {self._show_files}")
            log.info(f"Changed file detection: method=mr-diff, source=bitbucket-pr, files={len(self._show_files)}")
            return True
            
        except Exception as error:
            log.debug(f"Failed to get changed files via git diff (Bitbucket): {error}")
            return False

    def _detect_merge_commit_fallback(self) -> bool:
        """
        Detect changed files using merge-aware fallback for merge commits.
        
        This fallback is used when CI-specific MR variables are not present.
        It detects only true merge commits (multiple parents) and uses git diff.
        
        IMPORTANT LIMITATIONS:
        1. git show --name-only <merge-commit> does NOT list filenames (expected Git behavior)
        2. Only detects true merge commits (multiple parents), not squash merges
        3. Octopus merges (3+ parents): Uses first-parent diff only, may miss changes
        4. First-parent choice: Assumes main branch is first parent (typical but not guaranteed)
        
        WHY FIRST-PARENT:
        - merge^1 is typically the target branch (main/master)
        - merge^2+ are feature branches being merged in
        - Diffing against main shows "what changed" from main's perspective
        - This is the most useful for dependency scanning (what's new in main)
        
        Returns:
            True if detection was successful, False otherwise
        """
        # Check if this is a merge commit (multiple parents only)
        is_merge_commit = len(self.commit.parents) > 1
        
        if not is_merge_commit:
            return False
            
        try:
            # Guard: Ensure first parent is resolvable before attempting diff
            if not self.commit.parents:
                log.debug("Merge commit has no parents - cannot perform merge-aware diff")
                return False
                
            parent_commit = self.commit.parents[0]
            
            # Verify parent commit is accessible to prevent accidental huge diffs
            try:
                parent_sha = parent_commit.hexsha
                # Quick validation that parent exists and is accessible
                self.repo.commit(parent_sha)
            except Exception as parent_error:
                log.error(f"Cannot resolve parent commit {parent_commit}: {parent_error}")
                log.error("Merge-aware fallback failed - parent commit not accessible")
                return False
            
            diff_range = f'{parent_sha}..{self.commit.hexsha}'
            
            # Log warning for octopus merges (3+ parents) about first-parent limitation
            if len(self.commit.parents) > 2:
                log.warning(f"Octopus merge detected ({len(self.commit.parents)} parents). "
                           f"Using first-parent diff only - may not show all changes from all branches. "
                           f"Commit: {self.commit.hexsha[:8]}")
            
            log.debug(f"Attempting merge commit fallback: git diff --name-only {diff_range}")
            
            diff_files = self.repo.git.diff('--name-only', diff_range)
            self._show_files = diff_files.splitlines()
            self._detection_method = "merge-diff"
            
            log.debug(f"Changed files detected via git diff (merge commit): {self._show_files}")
            log.info(f"Changed file detection: method=merge-diff, source=merge-commit-fallback, files={len(self._show_files)}")
            return True
            
        except Exception as error:
            log.debug(f"Failed to get changed files via git diff (merge commit): {error}")
            return False

    def _detect_single_commit_fallback(self) -> None:
        """
        Final fallback to git show for single commits.
        
        IMPORTANT NOTE:
        git show --name-only <merge-commit> does NOT list filenames (expected Git behavior).
        This method should only be used for single-parent commits (regular commits).
        
        For merge commits without CI environment variables, use _detect_merge_commit_fallback()
        which implements git diff <parent^1>..<commit> to properly detect changed files.
        """
        log.debug(f"Attempting final fallback: git show {self.commit.hexsha[:8]} --name-only")
        
        self._show_files = self.repo.git.show(self.commit, name_only=True).splitlines()
        self._detection_method = "single-commit-show"
        
        log.debug(f"Changed files detected via git show: {self._show_files}")
        log.info(f"Changed file detection: method=single-commit-show, source=final-fallback, files={len(self._show_files)}")

    def _filter_and_set_changed_files(self) -> None:
        """Filter out empty strings and set the final changed_files list."""
        self._changed_files = []
        for item in self._show_files:
            if item != "":
                # Use relative path for glob matching
                self._changed_files.append(item)

    def _log_detection_results(self) -> None:
        """Log the final detection results for debugging."""
        log.debug(f"Changed file detection method: {self._detection_method}")
        log.debug(f"Final show_files: {self._show_files}")
        log.debug(f"Final changed_files: {self._changed_files}")
        
        # Add final decision summary log for support escalations
        # SCHEMA FROZEN: DO NOT CHANGE - used by monitoring/support tools
        # Format: DETECTION SUMMARY: method=<str> files=<int> sha=<8char> cmd="<git-command>"
        git_cmd = self._get_last_git_command()
        log.info(f"DETECTION SUMMARY: method={self._detection_method} files={len(self._changed_files)} sha={self.commit.hexsha[:8]} cmd=\"{git_cmd}\"")

    def _get_last_git_command(self) -> str:
        """Get the last git command that was executed for detection."""
        if self._detection_method == "mr-diff":
            # Check for different MR contexts
            gitlab_target = os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')
            gitlab_source = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
            github_base_ref = os.getenv('GITHUB_BASE_REF')
            github_head_ref = os.getenv('GITHUB_HEAD_REF')
            bitbucket_source = os.getenv('BITBUCKET_BRANCH')
            bitbucket_target = os.getenv('BITBUCKET_PR_DESTINATION_BRANCH')
            
            if gitlab_target and gitlab_source:
                return f"git diff --name-only origin/{gitlab_target}...origin/{gitlab_source}"
            elif github_base_ref and github_head_ref:
                return f"git diff --name-only origin/{github_base_ref}...origin/{github_head_ref}"
            elif bitbucket_source and bitbucket_target:
                return f"git diff --name-only origin/{bitbucket_target}...origin/{bitbucket_source}"
            else:
                return "git diff --name-only <unknown-range>"
                
        elif self._detection_method == "push-diff":
            github_before_sha = os.getenv('GITHUB_EVENT_BEFORE')
            github_sha = os.getenv('GITHUB_SHA')
            if github_before_sha and github_sha:
                return f"git diff --name-only {github_before_sha}..{github_sha}"
            else:
                return "git diff --name-only <unknown-range>"
                
        elif self._detection_method == "merge-diff":
            if len(self.commit.parents) > 0:
                parent_sha = self.commit.parents[0].hexsha
                return f"git diff --name-only {parent_sha}..{self.commit.hexsha}"
            else:
                return "git diff --name-only <no-parent>"
                
        elif self._detection_method == "single-commit-show":
            return f"git show --name-only {self.commit.hexsha}"
            
        else:
            return f"unknown command for method: {self._detection_method}"
    
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
    
    def get_default_branch_name(self) -> str:
        """
        Get the default branch name from the remote origin.
        
        Returns:
            Default branch name (e.g., 'main', 'master')
        """
        try:
            # Try to get the default branch from remote HEAD
            remote_head = self.repo.remotes.origin.refs.HEAD
            # Extract branch name from refs/remotes/origin/HEAD -> refs/remotes/origin/main
            default_branch = str(remote_head.reference).split('/')[-1]
            log.debug(f"Default branch detected: {default_branch}")
            return default_branch
        except Exception as error:
            log.debug(f"Could not determine default branch from remote: {error}")
            # Fallback: check common default branch names
            for branch_name in ['main', 'master']:
                try:
                    if f'origin/{branch_name}' in [str(ref) for ref in self.repo.remotes.origin.refs]:
                        log.debug(f"Using fallback default branch: {branch_name}")
                        return branch_name
                except:
                    continue
            
            # Last fallback: assume 'main'
            log.debug("Using final fallback default branch: main")
            return 'main'
    
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
            except:
                # Fallback to local branch
                try:
                    default_branch_ref = self.repo.heads[default_branch] 
                    default_branch_commit = default_branch_ref.commit
                except:
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