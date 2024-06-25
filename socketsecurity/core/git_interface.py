from git import Repo


class Git:
    repo: Repo
    path: str

    def __init__(self, path: str):
        self.path = path
        self.repo = Repo(path)
        assert self.repo
        self.head = self.repo.head
        self.reference = self.head.reference
        self.commit = self.reference.commit
        self.repo_name = self.repo.remotes.origin.url.split('.git')[0].split('/')[-1]
        self.branch = self.repo.active_branch
        self.author = self.commit.author
        self.commit_sha = self.commit.binsha
        self.commit_message = self.commit.message
        self.committer = self.commit.committer
        self.show_files = self.repo.git.show(self.commit, name_only=True, format="%n").splitlines()
        self.changed_files = []
        for item in self.show_files:
            if item != "":
                self.changed_files.append(item)
