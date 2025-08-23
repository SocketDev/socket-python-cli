import urllib.parse
import os

from git import Repo

from socketsecurity.core import log


class Git:
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
        gitlab_sha = os.getenv('CI_COMMIT_SHA')
        bitbucket_sha = os.getenv('BITBUCKET_COMMIT')
        ci_sha = github_sha or gitlab_sha or bitbucket_sha
        
        if ci_sha:
            try:
                self.commit = self.repo.commit(ci_sha)
                if github_sha:
                    env_source = "GITHUB_SHA"
                elif gitlab_sha:
                    env_source = "CI_COMMIT_SHA"
                else:
                    env_source = "BITBUCKET_COMMIT"
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
        # Detect changed files in PR/MR context for GitHub, GitLab, Bitbucket; fallback to git show
        self.show_files = []
        detected = False
        # GitHub Actions PR context
        github_base_ref = os.getenv('GITHUB_BASE_REF')
        github_head_ref = os.getenv('GITHUB_HEAD_REF')
        github_event_name = os.getenv('GITHUB_EVENT_NAME')
        github_before_sha = os.getenv('GITHUB_EVENT_BEFORE')  # previous commit for push
        github_sha = os.getenv('GITHUB_SHA')  # current commit
        if github_event_name == 'pull_request' and github_base_ref and github_head_ref:
            try:
                # Fetch both branches individually
                self.repo.git.fetch('origin', github_base_ref)
                self.repo.git.fetch('origin', github_head_ref)
                # Try remote diff first
                diff_range = f"origin/{github_base_ref}...origin/{github_head_ref}"
                try:
                    diff_files = self.repo.git.diff('--name-only', diff_range)
                    self.show_files = diff_files.splitlines()
                    log.debug(f"Changed files detected via git diff (GitHub PR remote): {self.show_files}")
                    detected = True
                except Exception as remote_error:
                    log.debug(f"Remote diff failed: {remote_error}")
                    # Try local branch diff
                    local_diff_range = f"{github_base_ref}...{github_head_ref}"
                    try:
                        diff_files = self.repo.git.diff('--name-only', local_diff_range)
                        self.show_files = diff_files.splitlines()
                        log.debug(f"Changed files detected via git diff (GitHub PR local): {self.show_files}")
                        detected = True
                    except Exception as local_error:
                        log.debug(f"Local diff failed: {local_error}")
            except Exception as error:
                log.debug(f"Failed to fetch branches or diff for GitHub PR: {error}")
        # Commits to default branch (push events)
        elif github_event_name == 'push' and github_before_sha and github_sha:
            try:
                diff_files = self.repo.git.diff('--name-only', f'{github_before_sha}..{github_sha}')
                self.show_files = diff_files.splitlines()
                log.debug(f"Changed files detected via git diff (GitHub push): {self.show_files}")
                detected = True
            except Exception as error:
                log.debug(f"Failed to get changed files via git diff (GitHub push): {error}")
        elif github_event_name == 'push':
            try:
                self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
                log.debug(f"Changed files detected via git show (GitHub push fallback): {self.show_files}")
                detected = True
            except Exception as error:
                log.debug(f"Failed to get changed files via git show (GitHub push fallback): {error}")
        # GitLab CI Merge Request context
        if not detected:
            gitlab_target = os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')
            gitlab_source = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
            if gitlab_target and gitlab_source:
                try:
                    self.repo.git.fetch('origin', gitlab_target, gitlab_source)
                    diff_range = f"origin/{gitlab_target}...origin/{gitlab_source}"
                    diff_files = self.repo.git.diff('--name-only', diff_range)
                    self.show_files = diff_files.splitlines()
                    log.debug(f"Changed files detected via git diff (GitLab): {self.show_files}")
                    detected = True
                except Exception as error:
                    log.debug(f"Failed to get changed files via git diff (GitLab): {error}")
        # Bitbucket Pipelines PR context
        if not detected:
            bitbucket_pr_id = os.getenv('BITBUCKET_PR_ID')
            bitbucket_source = os.getenv('BITBUCKET_BRANCH')
            bitbucket_dest = os.getenv('BITBUCKET_PR_DESTINATION_BRANCH')
            # BITBUCKET_BRANCH is the source branch in PR builds
            if bitbucket_pr_id and bitbucket_source and bitbucket_dest:
                try:
                    self.repo.git.fetch('origin', bitbucket_dest, bitbucket_source)
                    diff_range = f"origin/{bitbucket_dest}...origin/{bitbucket_source}"
                    diff_files = self.repo.git.diff('--name-only', diff_range)
                    self.show_files = diff_files.splitlines()
                    log.debug(f"Changed files detected via git diff (Bitbucket): {self.show_files}")
                    detected = True
                except Exception as error:
                    log.debug(f"Failed to get changed files via git diff (Bitbucket): {error}")
        # Fallback to git show for single commit
        if not detected:
            self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
            log.debug(f"Changed files detected via git show: {self.show_files}")
        self.changed_files = []
        for item in self.show_files:
            if item != "":
                # Use relative path for glob matching
                self.changed_files.append(item)
        
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