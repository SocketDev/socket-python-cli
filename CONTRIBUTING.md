# Contributing

## Development setup

Use Python 3.11 or newer and install
[`uv`](https://docs.astral.sh/uv/getting-started/installation/). From the
repository root, create the environment and install all development
dependencies:

```bash
uv sync --all-extras
```

Before opening a pull request, run:

```bash
make test
make lint
uv run hatch build
uv run python -m twine check dist/*
```

To develop against a local SDK checkout, set `SOCKET_SDK_PATH` if it is not at
`../socketdev`, then run `make first-time-local-setup`.

## Pull request validation

The `Package Check` workflow runs automatically for pull requests. It builds
and validates the distributions, smoke-tests the wheel, and uploads the
distributions as workflow artifacts. It does not publish a package or Docker
image.

## Publishing pull request previews

Preview publication is intentionally opt-in. Only request previews for code
that is trusted to run with the repository's publishing permissions.

For a pull request from this repository, apply the label for the artifact that
needs testing:

- `publish-preview` publishes a uniquely versioned `socketsecurity` prerelease
  to TestPyPI and adds or updates a pull request comment with the exact version
  and installation command.
- `publish-docker-preview` publishes the mutable
  `socketdev/cli:pr-<pull-request-number>` image to Docker Hub and adds or
  updates a pull request comment with the image tag.

Label-triggered publication is skipped for pull requests from forks. Each label
is handled as a separate event, so applying both labels starts two workflow
runs. Use manual dispatch instead when both artifacts should be published in a
single run.

The workflow reacts when a label is added; pushing another commit while the
label remains on the pull request does not publish a new preview. To publish the
new pull request head or retry a failed publication, remove the relevant label
and apply it again.

Maintainers can also open **Actions > Publish PR Preview > Run workflow**, enter
the pull request number, and choose whether to publish to TestPyPI, Docker Hub,
or both. When testing the CLI against an SDK preview, enter the exact TestPyPI
`socketdev` prerelease in `sdk_preview_version`; publish the SDK preview first
and allow time for TestPyPI to expose it before starting the CLI Docker preview.
