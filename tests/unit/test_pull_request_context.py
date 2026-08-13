from socketsecurity.core.pull_request import resolve_pull_request_context


def test_explicit_pr_number_wins_over_detected_context():
    context = resolve_pull_request_context(
        "github",
        "42",
        "acme/widgets",
        configured_explicit=True,
        env={
            "GITHUB_REF": "refs/pull/99/merge",
            "GITHUB_REPOSITORY": "acme/widgets",
        },
    )

    assert context.number == 42
    assert context.url == "https://github.com/acme/widgets/pull/42"


def test_explicit_zero_disables_pr_auto_detection():
    context = resolve_pull_request_context(
        "github",
        "0",
        "acme/widgets",
        configured_explicit=True,
        env={"GITHUB_REF": "refs/pull/99/merge"},
    )

    assert context.number == 0
    assert context.url is None


def test_buildkite_non_pr_sentinel_is_treated_as_no_pull_request():
    context = resolve_pull_request_context(
        "github",
        "false",
        "acme/widgets",
        configured_explicit=True,
        env={},
    )

    assert context.number == 0
    assert context.url is None


def test_github_context_is_detected_from_actions_environment():
    context = resolve_pull_request_context(
        "github",
        "0",
        None,
        env={
            "GITHUB_REF": "refs/pull/123/merge",
            "GITHUB_REPOSITORY": "acme/widgets",
            "GITHUB_SERVER_URL": "https://github.example.com",
        },
    )

    assert context.number == 123
    assert context.url == "https://github.example.com/acme/widgets/pull/123"


def test_gitlab_context_is_detected_from_merge_request_environment():
    context = resolve_pull_request_context(
        "gitlab",
        "0",
        None,
        env={
            "CI_MERGE_REQUEST_IID": "81",
            "CI_PROJECT_URL": "https://gitlab.example.com/acme/widgets",
        },
    )

    assert context.number == 81
    assert context.url == "https://gitlab.example.com/acme/widgets/-/merge_requests/81"


def test_azure_repos_context_uses_pull_request_id():
    context = resolve_pull_request_context(
        "azure",
        "0",
        None,
        env={
            "SYSTEM_PULLREQUEST_PULLREQUESTID": "17",
            "BUILD_REPOSITORY_URI": "https://dev.azure.com/acme/platform/_git/widgets",
        },
    )

    assert context.number == 17
    assert context.url == "https://dev.azure.com/acme/platform/_git/widgets/pullrequest/17"


def test_azure_fork_context_uses_target_repository_url():
    context = resolve_pull_request_context(
        "azure",
        "0",
        None,
        env={
            "SYSTEM_PULLREQUEST_PULLREQUESTID": "17",
            "BUILD_REPOSITORY_URI": "https://dev.azure.com/acme/platform/_git/widgets",
            "SYSTEM_PULLREQUEST_SOURCEREPOSITORYURI": (
                "https://dev.azure.com/contributor/forks/_git/widgets"
            ),
        },
    )

    assert context.number == 17
    assert context.url == "https://dev.azure.com/acme/platform/_git/widgets/pullrequest/17"


def test_azure_pipeline_with_github_repo_uses_pull_request_number():
    context = resolve_pull_request_context(
        "azure",
        "0",
        None,
        env={
            "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER": "23",
            "SYSTEM_PULLREQUEST_PULLREQUESTID": "98765",
            "BUILD_REPOSITORY_URI": "https://github.com/acme/widgets.git",
        },
    )

    assert context.number == 23
    assert context.url == "https://github.com/acme/widgets/pull/23"


def test_explicit_azure_github_pr_number_still_uses_github_url_shape():
    context = resolve_pull_request_context(
        "azure",
        "23",
        None,
        configured_explicit=True,
        env={"BUILD_REPOSITORY_URI": "https://github.com/acme/widgets.git"},
    )

    assert context.number == 23
    assert context.url == "https://github.com/acme/widgets/pull/23"


def test_non_pr_run_has_no_context():
    context = resolve_pull_request_context("azure", "0", "acme/widgets", env={})

    assert context.number == 0
    assert context.url is None


# ---------------------------------------------------------------------------
# Provider-neutral CI (Buildkite). The provider comes from --integration and the
# PR number from --pr-number; only the repository slug has to be recovered from
# the checkout URL, because config.repo is a bare repository name with no owner.
# ---------------------------------------------------------------------------


def test_buildkite_github_repo_url_is_derived_from_the_checkout_remote():
    context = resolve_pull_request_context(
        "github",
        "42",
        "widgets",
        configured_explicit=True,
        env={"BUILDKITE_REPO": "git@github.com:acme/widgets.git"},
    )

    assert context.number == 42
    assert context.url == "https://github.com/acme/widgets/pull/42"


def test_buildkite_github_enterprise_host_is_taken_from_the_remote():
    context = resolve_pull_request_context(
        "github",
        "42",
        "widgets",
        configured_explicit=True,
        env={"BUILDKITE_REPO": "https://github.example.com/acme/widgets.git"},
    )

    assert context.url == "https://github.example.com/acme/widgets/pull/42"


def test_github_actions_environment_wins_over_the_checkout_remote():
    context = resolve_pull_request_context(
        "github",
        "42",
        "widgets",
        configured_explicit=True,
        env={
            "GITHUB_REPOSITORY": "acme/widgets",
            "GITHUB_SERVER_URL": "https://github.example.com",
            "BUILDKITE_REPO": "git@github.com:stale/mirror.git",
        },
    )

    assert context.url == "https://github.example.com/acme/widgets/pull/42"


def test_buildkite_gitlab_repo_url_keeps_nested_subgroups():
    context = resolve_pull_request_context(
        "gitlab",
        "81",
        "widgets",
        configured_explicit=True,
        env={"BUILDKITE_REPO": "ssh://git@gitlab.example.com/acme/platform/widgets.git"},
    )

    assert context.url == "https://gitlab.example.com/acme/platform/widgets/-/merge_requests/81"


def test_gitlab_ci_project_url_wins_over_the_checkout_remote():
    context = resolve_pull_request_context(
        "gitlab",
        "81",
        "widgets",
        configured_explicit=True,
        env={
            "CI_PROJECT_URL": "https://gitlab.example.com/acme/widgets",
            "BUILDKITE_REPO": "git@gitlab.example.com:stale/mirror.git",
        },
    )

    assert context.url == "https://gitlab.example.com/acme/widgets/-/merge_requests/81"


def test_bare_repository_name_alone_yields_no_url():
    """config.repo has no owner segment, so it cannot stand in for a slug."""
    context = resolve_pull_request_context(
        "github", "42", "widgets", configured_explicit=True, env={}
    )

    assert context.number == 42
    assert context.url is None
