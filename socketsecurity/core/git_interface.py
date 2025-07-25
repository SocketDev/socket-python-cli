import urllib.parse
import os

from git import Repo

from socketsecurity.core import log


class Git:
    repo: Repo
    path: str

    def __init__(self, path: str):
        self.path = path
        self.repo = Repo(path)
        assert self.repo
        self.head = self.repo.head
        
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
        self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
        self.changed_files = []
        for item in self.show_files:
            if item != "":
                full_path = f"{self.path}/{item}"
                self.changed_files.append(full_path)
        
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
