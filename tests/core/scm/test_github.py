from unittest.mock import MagicMock, mock_open, patch

import pytest

from socketsecurity.core.exceptions import APIAccessDenied
from socketsecurity.core.scm.github import Github, GithubConfig


@pytest.fixture
def mock_env_vars():
    return {
        "GH_API_TOKEN": "fake-token",
        "GITHUB_SHA": "abc123",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_WORKSPACE": "/workspace",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_REF_NAME": "main",
        "DEFAULT_BRANCH": "true",
        "PR_NUMBER": "123",
        "PR_NAME": "test-pr",
        "COMMIT_MESSAGE": "test commit",
        "GITHUB_ACTOR": "test-user",
        "GITHUB_ENV": "/github/env",
        "GITHUB_REPOSITORY_OWNER": "owner",
        "EVENT_ACTION": "opened"
    }

@pytest.fixture
def github_instance(mock_env_vars):
    with patch.dict('os.environ', mock_env_vars), \
         patch('socketsecurity.core.scm.github.github_repository', 'owner/repo'), \
         patch('socketsecurity.core.scm.github.github_repository_owner', 'owner'), \
         patch('socketsecurity.core.scm.github.github_sha', 'abc123'), \
         patch('socketsecurity.core.scm.github.github_api_url', 'https://api.github.com'), \
         patch('socketsecurity.core.scm.github.github_ref_type', 'branch'), \
         patch('socketsecurity.core.scm.github.github_event_name', 'pull_request'), \
         patch('socketsecurity.core.scm.github.github_workspace', '/workspace'), \
         patch('socketsecurity.core.scm.github.github_ref_name', 'main'), \
         patch('socketsecurity.core.scm.github.default_branch', 'true'), \
         patch('socketsecurity.core.scm.github.is_default_branch', True), \
         patch('socketsecurity.core.scm.github.pr_number', '123'), \
         patch('socketsecurity.core.scm.github.pr_name', 'test-pr'), \
         patch('socketsecurity.core.scm.github.commit_message', 'test commit'), \
         patch('socketsecurity.core.scm.github.github_actor', 'test-user'), \
         patch('socketsecurity.core.scm.github.github_env', '/github/env'), \
         patch('socketsecurity.core.scm.github.gh_api_token', 'fake-token'), \
         patch('socketsecurity.core.scm.github.event_action', 'opened'):
        return Github()

class TestGithubConfig:
    def test_from_env_success(self, mock_env_vars):
        with patch.dict('os.environ', mock_env_vars):
            config = GithubConfig.from_env()
            assert config.token == "fake-token"
            assert config.repository == "repo"
            assert config.default_branch is True

    def test_from_env_missing_token(self):
        with patch.dict('os.environ', {"GH_API_TOKEN": ""}), \
             pytest.raises(SystemExit) as exc:
            GithubConfig.from_env()
        assert exc.value.code == 2

class TestGithubEventTypes:
    @pytest.mark.parametrize("event_name,pr_number,event_action,expected", [
        ("push", None, None, "main"),
        ("push", "123", None, "diff"),
        ("pull_request", None, "opened", "diff"),
        ("pull_request", None, "synchronize", "diff"),
        ("issue_comment", None, None, "comment"),
    ])
    def test_check_event_type_valid(self, event_name, pr_number, event_action, expected):
        with patch('socketsecurity.core.scm.github.github_event_name', event_name), \
             patch('socketsecurity.core.scm.github.pr_number', pr_number), \
             patch('socketsecurity.core.scm.github.event_action', event_action):
            assert Github.check_event_type() == expected

    def test_check_event_type_unsupported_pr_action(self):
        with patch('socketsecurity.core.scm.github.github_event_name', 'pull_request'), \
             patch('socketsecurity.core.scm.github.event_action', 'closed'), \
             pytest.raises(SystemExit) as exc:
            Github.check_event_type()
        assert exc.value.code == 0

    def test_check_event_type_unknown(self):
        with patch('socketsecurity.core.scm.github.github_event_name', 'unknown'), \
             pytest.raises(SystemExit) as exc:
            Github.check_event_type()
        assert exc.value.code == 0

class TestGithubComments:
    @pytest.fixture
    def mock_do_request(self):
        with patch('socketsecurity.core.scm.github.do_request') as mock:
            yield mock

    @pytest.fixture(autouse=True)
    def setup_globals(self):
        with patch.multiple('socketsecurity.core.scm.github',
            github_repository='owner/repo',
            github_repository_owner='owner',
            pr_number='123',
            github_api_url='https://api.github.com',
            github_env='/github/env',
            headers={'Authorization': 'Bearer fake-token'}):
            yield

    def test_post_comment(self, mock_do_request):
        Github.post_comment("test comment")
        mock_do_request.assert_called_once()
        assert mock_do_request.call_args[1]["method"] == "POST"

    def test_update_comment(self, mock_do_request):
        Github.update_comment("updated comment", "123")
        mock_do_request.assert_called_once()
        assert mock_do_request.call_args[1]["method"] == "PATCH"

    def test_write_new_env(self):
        m = mock_open()
        with patch('builtins.open', m):
            Github.write_new_env("TEST", "value\nwith\nnewlines")
        m.assert_called_once_with("/github/env", "a")
        handle = m()
        handle.write.assert_called_once_with("TEST=value\\nwith\\nnewlines")

    def test_get_comments_for_pr_success(self, mock_do_request):
        mock_response = MagicMock()
        mock_response.json.return_value = [{
            "id": 1,
            "body": "test comment",
            "user": {"login": "test-user"}
        }]
        mock_do_request.return_value = mock_response

        comments = Github.get_comments_for_pr("repo", "123")
        assert isinstance(comments, dict)
        mock_do_request.assert_called_once()

    def test_get_comments_for_pr_error(self, mock_do_request):
        mock_response = MagicMock()
        mock_response.json.return_value = {"error": "test error"}
        mock_do_request.return_value = mock_response

        comments = Github.get_comments_for_pr("repo", "123")
        assert comments == {}

class TestGithubReactions:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch.dict('socketsecurity.core.__dict__', {'encoded_key': 'fake-encoded-key'}), \
             patch('requests.request') as mock_request, \
             patch.multiple('socketsecurity.core.scm.github',
                github_repository='owner/repo',
                github_repository_owner='owner',
                pr_number='123',
                github_api_url='https://api.github.com',
                gh_api_token='fake-token',
                headers={'Authorization': 'Bearer fake-token'}):

            # Set up a default successful response
            mock_response = MagicMock()
            mock_response.json.return_value = []
            mock_response.status_code = 200
            mock_response.text = ""
            mock_request.return_value = mock_response

            yield mock_request

    def test_post_reaction(self, setup_mocks):
        mock_request = setup_mocks
        Github.post_reaction(123)
        mock_request.assert_called_once()
        assert mock_request.call_args[0][0] == "POST"
        assert '"content": "+1"' in mock_request.call_args[1]["data"]

    def test_comment_reaction_exists_true(self, setup_mocks):
        mock_request = setup_mocks
        mock_response = MagicMock()
        mock_response.json.return_value = [{"content": ":thumbsup:"}]
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        assert Github.comment_reaction_exists(123) is True

    def test_comment_reaction_exists_false(self, setup_mocks):
        mock_request = setup_mocks
        mock_response = MagicMock()
        mock_response.json.return_value = [{"content": ":thumbsdown:"}]
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        assert Github.comment_reaction_exists(123) is False

    def test_comment_reaction_exists_error(self, setup_mocks):
        mock_request = setup_mocks
        mock_request.side_effect = APIAccessDenied("Unauthorized")

        with patch('socketsecurity.core.log.error'):  # Suppress error logs
            result = Github.comment_reaction_exists(123)
            assert result is False