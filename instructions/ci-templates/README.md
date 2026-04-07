# CI Templates for `socket-sdk-python`

These files are ready-to-commit templates intended for the SDK repo:
- `sdk-python-tests.yml`
- `cli-compat-on-sdk-pr.yml`

## How to use
1. Copy each file into `socket-sdk-python/.github/workflows/`.
2. Adjust branch filters and path filters if needed.
3. Add required checks in branch protection after a trial period.

## Notes
- `cli-compat-on-sdk-pr.yml` calls the CLI reusable workflow:
  - `SocketDev/socket-python-cli/.github/workflows/reusable-cli-compat.yml@main`
- It triggers compatibility checks when:
  - SDK surface files changed, or
  - PR has label `needs-cli-compat`.
