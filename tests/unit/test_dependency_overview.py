from socketsecurity.core.classes import Diff, Package, Purl
from socketsecurity.core.messages import Messages


def _make_purl(name: str, scores) -> Purl:
    return Purl(
        id=f"pkg:npm/{name}@1.0.0",
        name=name,
        version="1.0.0",
        ecosystem="npm",
        direct=True,
        introduced_by=[("direct", "package.json")],
        author=["test-author"],
        size=1000,
        transitives=0,
        url=f"https://socket.dev/npm/package/{name}/overview/1.0.0",
        purl=f"pkg:npm/{name}@1.0.0",
        scores=scores,
    )


def test_package_from_diff_artifact_normalizes_null_score():
    package = Package.from_diff_artifact(
        {
            "id": "pkg:npm/example@1.0.0",
            "name": "example",
            "version": "1.0.0",
            "type": "npm",
            "diffType": "added",
            "score": None,
            "alerts": [],
            "author": [],
            "topLevelAncestors": [],
            "direct": True,
            "manifestFiles": [],
        }
    )

    assert package.score == {}


def test_dependency_overview_template_defaults_missing_or_null_scores(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    diff = Diff(
        id="test-diff",
        diff_url="https://socket.dev/test-diff",
        new_packages=[
            _make_purl("missing-scores", None),
            _make_purl(
                "partial-scores",
                {
                    "supplyChain": 0.42,
                    "vulnerability": None,
                },
            ),
        ],
        removed_packages=[],
        new_alerts=[],
    )

    comment = Messages.dependency_overview_template(diff)

    assert "Socket Security: Dependency Overview" in comment
    assert "score-42.svg" in comment
    assert "score-100.svg" in comment
    assert "score-10000.svg" not in comment
