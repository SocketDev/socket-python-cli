# Contributing

## Development setup

Use Python 3.11 or newer and install
[`uv`](https://docs.astral.sh/uv/getting-started/installation/). From the
repository root, create the environment and install all development
dependencies:

```bash
uv sync --all-extras
```

Install the git hooks once per clone:

```bash
make hooks
```

Before opening a pull request, run:

```bash
make lint
make test
uv run hatch build
uv run python -m twine check dist/*
```

To develop against a local SDK checkout, set `SOCKET_SDK_PATH` if it is not at
`../socketdev`, then run `make first-time-local-setup`.

## Linting

Ruff reads the rule set from `pyproject.toml`. Its version is pinned in the
project's `dev` extra and resolved in `uv.lock` for local commands, pre-commit,
and CI.

- `make lint` checks linting and formatting across the repository.
- `make lint-fix` applies safe lint fixes; `make format` formats Python files.
- The pre-commit hooks fix and format the files in a commit. When they modify a
  file, review and stage the edits before committing again.
- The `Lint` workflow checks the whole repository on every pull request and
  every push to `main`, including `.hooks/`, benchmarks, and end-to-end tooling.
  It has no path filter, so it can report on every pull request when configured
  as a required check.

The formatter uses a line length of 120. `E501` and `W291`/`W293` are not
selected: whitespace inside strings can affect help text, logs, and rendered
Markdown. In particular, trailing double-spaces in pull request comment strings
are Markdown hard line breaks.

### One trap worth knowing

Never run `ruff check --select <narrow-list> --fix` with `RUF100` in the select.
With a narrow select, RUF100 considers every `# noqa` for a *non-selected* rule
to be unused and deletes it -- silently stripping the complexity suppressions
across the repository. Run `make lint-fix`, which uses the full configured rule
set, instead of hand-rolling a `--select`.

### Complexity limits

Two rules bound how large a single function may get:

| Rule | Limit | What it measures |
| --- | --- | --- |
| `C901` | 12 | Cyclomatic complexity: independent paths through a function. |
| `PLR0913` | 8 | Arguments in a function definition. |

Functions that already exceed these limits carry an explicit
`# noqa: C901` / `# noqa: PLR0913` on their `def` line. Treat these as a refactoring backlog:

- **Do not add a new suppression.** If a function you are writing trips the
  limit, split it.
- **Suppressions clean themselves up.** `RUF100` fails the build on a `# noqa`
  that no longer applies, so refactoring a function back under the limit forces
  the marker to be removed.

To see what is left:

```bash
grep -rn 'noqa: C901\|noqa: PLR0913' socketsecurity/ tests/
```

## Pull request validation

The `Package Check` workflow runs automatically for pull requests. It builds
and validates the distributions, smoke-tests the wheel, and uploads the
distributions as workflow artifacts. It does not publish a package or Docker
image.

## Build tooling and release notes

Keep the Hatch and Hatchling pins in `.github/actions/setup-hatch/action.yml`
aligned with the `dev` extra and build backend in `pyproject.toml`.

The `Version Check` workflow enforces release-version checks for changes to
`socketsecurity/`, `pyproject.toml`, or `uv.lock`. A pull request can share
`main`'s unreleased version. CI and documentation changes alone do not require
a package version bump. Version extraction accepts single- and double-quoted
`__version__` declarations.

Keep changelog entries short and focused on observable CLI, dashboard, or scan
log behavior. Document contributor setup and CI policies in this guide, and
describe workflow implementation changes in the pull request description.

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

Both label-triggered and manually dispatched previews are limited to open pull
requests whose branches belong to this repository. Each label is handled as a
separate event, so applying both labels starts two workflow runs. Use manual
dispatch instead when both artifacts should be published in a single run.

The workflow reacts when a label is added; pushing another commit while the
label remains on the pull request does not publish a new preview. To publish the
new pull request head or retry a failed publication, remove the relevant label
and apply it again.

Maintainers can also open **Actions > Publish PR Preview > Run workflow**, run
it from the repository's default branch, enter the pull request number, and
choose whether to publish to TestPyPI, Docker Hub, or both. When testing the CLI
against an SDK preview, enter the exact TestPyPI `socketdev` prerelease in
`sdk_preview_version`; publish the SDK preview first and allow time for
TestPyPI to expose it before starting the CLI Docker preview.
