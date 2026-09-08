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

Ruff is the only linter. It runs in three places, all reading the same
configuration from `pyproject.toml` and the same version pinned in
`[project.optional-dependencies].dev`:

- `make lint` locally,
- the `ruff-check` pre-commit hook, on the files a commit touches,
- the `Lint` workflow, on every pull request and every push to `main`.

The pre-commit hook applies ruff's safe fixes and then fails the commit, leaving
the edits unstaged so they get read before they land. CI is the backstop for
commits made with `--no-verify` or without hooks installed.

`ruff format` is enforced the same way. It owns line length (120) and
whitespace, so the linter does not duplicate those checks: `E501` and `W291`/
`W293` are deliberately not selected. Everything the formatter cannot reflow is
a string literal -- argparse help text, log messages, the Markdown used to build
pull request comments -- where rewrapping risks silently changing text that
customers read.

The pull request comment markup is the clearest case. It uses trailing
double-spaces as Markdown hard line breaks, so stripping them takes the rendered
comment from two lines to one and runs the "Caution" banner into the body text:

```
> **Caution**··
> **Review the following alerts detected in dependencies.**··
```

Rendered with those two trailing spaces the banner sits on its own line. Without
them both lines collapse into a single paragraph. Whitespace inside a string is
content, and the formatter is right to leave it alone.

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
| `C901` | 12 | Cyclomatic complexity: independent paths through a function, which is also the number of tests needed to cover it. |
| `PLR0913` | 8 | Arguments in a function definition. |

Functions that already exceed these limits carry an explicit
`# noqa: C901` / `# noqa: PLR0913` on their `def` line. That list is a backlog,
not a precedent:

- **Do not add a new suppression.** If a function you are writing trips the
  limit, split it. This matters most for generated or model-assisted code, where
  branches accumulate quickly and nothing pushes back.
- **Suppressions clean themselves up.** `RUF100` fails the build on a `# noqa`
  that no longer applies, so refactoring a function back under the limit forces
  the marker to be removed. The backlog can only shrink.

To see what is left:

```bash
grep -rn 'noqa: C901\|noqa: PLR0913' socketsecurity/ tests/
```

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
