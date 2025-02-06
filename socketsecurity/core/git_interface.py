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
        
        # Use GITHUB_SHA if available, otherwise fall back to head commit
        github_sha = os.getenv('GITHUB_SHA')
        if github_sha:
            try:
                self.commit = self.repo.commit(github_sha)
            except Exception as error:
                log.debug(f"Failed to get commit from GITHUB_SHA: {error}")
                self.commit = self.head.commit
        else:
            self.commit = self.head.commit
        
        self.repo_name = self.repo.remotes.origin.url.split('.git')[0].split('/')[-1]
        try:
            self.branch = self.head.reference
            urllib.parse.unquote(str(self.branch))
        except Exception as error:
            self.branch = None
            log.debug(error)
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

    @property
    def commit_str(self) -> str:
        """Return commit SHA as a string"""
        return self.commit.hexsha
