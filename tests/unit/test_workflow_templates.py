"""The GitHub Actions examples stay pinned, current, and safe to require.

Dependabot updates the actions in `.github/workflows`, but not the copy-paste
templates in `workflows/` or the snippets in the docs, which is how the templates
fell four majors behind. These tests fail when an example uses an unpinned action
or a different commit than the repository's own CI, so a Dependabot bump surfaces
the examples that need the same update.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = sorted((ROOT / "workflows").glob("github-actions*.yml"))
EXAMPLES = TEMPLATES + [ROOT / "docs" / "ci-cd.md"]
USES = re.compile(r"uses:\s*(?P<action>[\w.-]+/[\w./-]+)@(?P<ref>\S+)(?P<comment>[^\n]*)")
PINNED = re.compile(r"^[0-9a-f]{40}$")


def _uses(path):
    return [m.groupdict() | {"path": path.relative_to(ROOT)} for m in USES.finditer(path.read_text())]


def _ci_pins():
    pins = {}
    files = list((ROOT / ".github" / "workflows").glob("*.yml"))
    files += list((ROOT / ".github" / "actions").glob("*/action.yml"))
    for path in files:
        for use in _uses(path):
            if PINNED.match(use["ref"]):
                pins.setdefault(use["action"], set()).add(use["ref"])
    return pins


def test_the_templates_exist():
    assert {path.name for path in TEMPLATES} == {
        "github-actions.yml",
        "github-actions-push.yml",
        "github-actions-comments.yml",
    }


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_examples_pin_actions_to_a_commit_with_its_version(path):
    unpinned = [
        f"{use['path']}: {use['action']}@{use['ref']}"
        for use in _uses(path)
        if not PINNED.match(use["ref"]) or not re.search(r"#\s*v\d", use["comment"])
    ]
    assert not unpinned, "pin these to a full commit SHA with a `# vX.Y.Z` comment: " + ", ".join(unpinned)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_examples_use_the_same_commit_as_ci(path):
    pins = _ci_pins()
    stale = [
        f"{use['path']}: {use['action']}@{use['ref'][:12]} (CI uses "
        f"{', '.join(sorted(ref[:12] for ref in pins[use['action']]))})"
        for use in _uses(path)
        if use["action"] in pins and use["ref"] not in pins[use["action"]]
    ]
    assert not stale, "update these to the commit .github/workflows uses: " + "; ".join(stale)


def test_only_the_pull_request_workflow_reports_the_required_check():
    """GitHub counts a skipped job as passing, so the required check needs its own workflow."""
    pr_workflow = (ROOT / "workflows" / "github-actions.yml").read_text()
    on_block = re.search(r"^on:\n((?:[ \t]+.*\n|\n)*)", pr_workflow, re.M).group(1)
    triggers = re.findall(r"^  (\w+):", on_block, re.M)
    assert triggers == ["pull_request"]
    for path in TEMPLATES:
        names = re.findall(r"^  ([\w-]+):\n|^    name: ([\w-]+)$", path.read_text(), re.M)
        reported = {job or name for job, name in names}
        if path.name == "github-actions.yml":
            assert "socket-security" in reported
        else:
            assert "socket-security" not in reported, f"{path.name} reports the required check name"
