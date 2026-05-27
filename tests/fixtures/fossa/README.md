# FOSSA reference fixtures

Real `fossa analyze` and `fossa report --json attribution` artifacts captured
from a representative Azure DevOps FOSSA pipeline run, used as the
structural-parity baseline for `--legal-format fossa` output.

Customer-identifying values (org IDs, project names) have been sanitized; the
structural shape, key sets, value types, and per-field cardinality match the
real artifacts byte-for-byte aside from those substitutions.

- `fossa-analyze-populated.json` — composed FOSSA analyze artifact with
  vulnerabilities present.
- `fossa-analyze-empty.json` — composed FOSSA analyze artifact with zero
  vulnerabilities.
- `fossa-sbom-populated.json` — `fossa report --json attribution` output with
  direct + deep dependencies.
- `fossa-sbom-empty-deep.json` — attribution output with empty
  `deepDependencies`.
