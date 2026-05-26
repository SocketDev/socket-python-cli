"""Structural parity tests: assert our FOSSA-shaped output matches real FOSSA artifact shapes.

These tests load real FOSSA artifacts captured from a customer pipeline and compare them
against our --legal-format fossa output by shape (key sets + value types), not by value.
A value-level golden test would be too brittle; the goal is to catch structural drift.
"""
from __future__ import annotations

import json
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "fossa"


def _load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


def test_fixtures_present_and_parseable():
    """Sanity: all four FOSSA reference fixtures load as JSON objects."""
    for name in (
        "fossa-analyze-populated.json",
        "fossa-analyze-empty.json",
        "fossa-sbom-populated.json",
        "fossa-sbom-empty-deep.json",
    ):
        data = _load(name)
        assert isinstance(data, dict), f"{name} should be a JSON object at the top level"


def test_analyze_fixture_top_level_shape():
    """The real FOSSA analyze artifact has exactly these top-level keys."""
    data = _load("fossa-analyze-populated.json")
    assert set(data.keys()) == {"project", "vulnerability", "licensing", "quality"}
    assert "risk" not in data  # FOSSA API 400s on risk category; key never appears


def test_sbom_fixture_top_level_shape():
    """The real FOSSA attribution artifact has exactly these 5 top-level keys."""
    data = _load("fossa-sbom-populated.json")
    assert set(data.keys()) == {
        "copyrightsByLicense",
        "deepDependencies",
        "directDependencies",
        "licenses",
        "project",
    }


def test_our_analyze_matches_fossa_analyze_top_level_keys():
    """Our build_fossa_report_payload top-level keyset matches the real fixture."""
    from socketsecurity.fossa_compat import build_fossa_report_payload
    from socketsecurity.config import CliConfig
    from socketsecurity.core.classes import Diff
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    ours = build_fossa_report_payload(Diff(), config)
    theirs = _load("fossa-analyze-empty.json")
    assert set(ours.keys()) == set(theirs.keys())


def test_our_analyze_project_keys_match():
    from socketsecurity.fossa_compat import build_fossa_report_payload
    from socketsecurity.config import CliConfig
    from socketsecurity.core.classes import Diff
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    ours = build_fossa_report_payload(Diff(), config)
    theirs = _load("fossa-analyze-empty.json")
    assert set(ours["project"].keys()) == set(theirs["project"].keys())


def test_our_sbom_matches_fossa_sbom_top_level_keys():
    from socketsecurity.fossa_compat import build_fossa_attribution_payload
    from socketsecurity.config import CliConfig
    from socketsecurity.core.classes import Diff
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    ours = build_fossa_attribution_payload(Diff(), config)
    theirs = _load("fossa-sbom-populated.json")
    assert set(ours.keys()) == set(theirs.keys())


def test_our_sbom_project_keys_match():
    from socketsecurity.fossa_compat import build_fossa_attribution_payload
    from socketsecurity.config import CliConfig
    from socketsecurity.core.classes import Diff
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    ours = build_fossa_attribution_payload(Diff(), config)
    theirs = _load("fossa-sbom-populated.json")
    assert set(ours["project"].keys()) == set(theirs["project"].keys())


def test_our_sbom_dependency_keys_match_when_populated():
    """When we have at least one dependency, its keyset matches a real FOSSA dependency entry."""
    from socketsecurity.fossa_compat import build_fossa_attribution_payload
    from socketsecurity.config import CliConfig
    from socketsecurity.core.classes import Diff, Package
    pkg = Package(
        type="pypi", name="x", version="1.0", id="pid",
        score={}, alerts=[], direct=True,
    )
    diff = Diff(packages={"pid": pkg})
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    ours = build_fossa_attribution_payload(diff, config)
    theirs = _load("fossa-sbom-populated.json")
    our_dep = ours["directDependencies"][0]
    their_dep = theirs["directDependencies"][0]
    assert set(our_dep.keys()) == set(their_dep.keys())
