# Development guide

## Local setup

This project uses `pyproject.toml` and `uv.lock` for dependency management.

### Standard setup (PyPI dependencies)

```bash
pyenv local 3.11
make first-time-setup
```

### Local SDK development setup

```bash
pyenv local 3.11
SOCKET_SDK_PATH=~/path/to/socketdev make first-time-local-setup
```

Default local SDK path is `../socketdev` when `SOCKET_SDK_PATH` is not set.

## Ongoing workflows

After dependency changes:

```bash
make update-deps
```

After pulling latest changes:

```bash
make sync-all
```

Run tests:

```bash
make test
```

Run lint/format checks:

```bash
make lint
```

## Make targets

High-level:

- `make first-time-setup`
- `make first-time-local-setup`
- `make update-lock`
- `make sync-all`
- `make dev-setup`

Implementation:

- `make local-dev`
- `make setup`
- `make sync`
- `make clean`
- `make test`
- `make lint`

## Environment variables

Core:

- `SOCKET_SECURITY_API_TOKEN` (also supports `SOCKET_SECURITY_API_KEY`, `SOCKET_API_KEY`, `SOCKET_API_TOKEN`)
- `SOCKET_SDK_PATH` (default `../socketdev`)

GitLab:

- `GITLAB_TOKEN`
- `CI_JOB_TOKEN`

## Manual setup (without `make`)

```bash
python -m venv .venv
source .venv/bin/activate
uv sync
uv add --dev pre-commit
pre-commit install
```

## Related docs

- CLI quick start: [`../README.md`](../README.md)
- CI/CD usage: [`ci-cd.md`](ci-cd.md)
- Full CLI reference: [`cli-reference.md`](cli-reference.md)
- Troubleshooting: [`troubleshooting.md`](troubleshooting.md)
