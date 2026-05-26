# FOSSA reference fixtures

Captured from a UiPath Azure DevOps pipeline (CE-199, build 12109922) for parity testing.

- `fossa-analyze-populated.json` — composed FOSSA analyze artifact with 11 vulnerabilities.
- `fossa-analyze-empty.json` — composed FOSSA analyze artifact with zero vulnerabilities.
- `fossa-sbom-populated.json` — `fossa report --json attribution` output with direct + deep dependencies.
- `fossa-sbom-empty-deep.json` — attribution output with empty `deepDependencies`.

Source assets retained at `assets/` (gitignored) for reference. These four files are the structural-parity baseline.
