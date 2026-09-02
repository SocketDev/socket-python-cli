"""An unparseable `.socket.facts.json` must not block a run or leave a PR comment.

When the API cannot parse an uploaded facts file it adds a synthetic
`generic/invalid-socket-facts@1.0.0` artifact carrying a blocking alert, which the CLI then
reports as a newly added blocking package with no manifest and no introducer. The CLI was
also handing the API an unparseable file itself: the placeholder it uploads for scans with
no manifest files was zero bytes.

These tests cover both the placeholder (`empty_head_scan_file`) and the marker filtering.
"""
import copy
import json
import os

import pytest
from socketdev.fullscans import FullScanStreamResponse, StreamDiffResponse

from socketsecurity.core import (
    INVALID_FACTS_MARKER_NAME,
    INVALID_FACTS_MARKER_TYPE,
    SOCKET_FACTS_FILENAME,
    Core,
)
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def core(mock_sdk_with_responses):
    return Core(config=SocketConfig(api_key="test_key"), sdk=mock_sdk_with_responses)


def make_marker_artifact(diff_type="added", artifact_id="invalid-facts-1"):
    """The artifact the API returns for an unparseable facts file."""
    return {
        "diffType": diff_type,
        "type": INVALID_FACTS_MARKER_TYPE,
        "name": INVALID_FACTS_MARKER_NAME,
        "version": "1.0.0",
        "id": artifact_id,
        "direct": True,
        "manifestFiles": [],
        "topLevelAncestors": [],
        "license": "",
        "licenseDetails": [],
        "author": [],
        "size": 0,
        "score": {
            "supplyChain": 0,
            "quality": 0,
            "maintenance": 0,
            "vulnerability": 0,
            "license": 0,
            "overall": 0,
        },
        "scores": {
            "supplyChain": 0,
            "quality": 0,
            "maintenance": 0,
            "vulnerability": 0,
            "license": 0,
            "overall": 0,
        },
        "alerts": [
            {
                "key": "invalid_facts_alert_1",
                "type": "generic",
                "severity": "high",
                "category": "supplyChainRisk",
                "action": "error",
            }
        ],
    }


# --- The placeholder the CLI uploads ----------------------------------------------------


def test_empty_head_scan_file_is_parseable_json():
    """The placeholder must parse as a facts document, or the API answers with the marker.

    A zero-byte file (the old behaviour) is what produced the invalid-socket-facts artifact
    in the first place.
    """
    (path,) = Core.empty_head_scan_file()

    assert os.path.basename(path) == SOCKET_FACTS_FILENAME, (
        "the API rejects unsupported filenames, so the placeholder basename is load-bearing"
    )
    with open(path) as f:
        assert json.load(f) == {"components": []}


def test_empty_head_scan_file_is_unique_per_call():
    """Concurrent runs must not share one placeholder path.

    The path used to be a fixed `$TMPDIR/.socket.facts.json`, so two CLI invocations sharing
    a temp dir could delete or truncate each other's placeholder mid-upload.
    """
    (first,) = Core.empty_head_scan_file()
    (second,) = Core.empty_head_scan_file()

    assert first != second
    # Deleting one (what the call sites do after upload) leaves the other intact.
    os.unlink(first)
    assert os.path.isfile(second)


# --- The marker predicate ---------------------------------------------------------------


class FakeArtifact:
    def __init__(self, type, name):
        self.type = type
        self.name = name


@pytest.mark.parametrize(
    "artifact_type,artifact_name,expected",
    [
        (INVALID_FACTS_MARKER_TYPE, INVALID_FACTS_MARKER_NAME, True),
        ("pypi", "requests", False),
        # A real generic package, and a same-named package from another ecosystem, are both
        # ordinary dependencies - only the exact type+name pair is the API's marker.
        (INVALID_FACTS_MARKER_TYPE, "some-tarball", False),
        ("npm", INVALID_FACTS_MARKER_NAME, False),
    ],
)
def test_is_invalid_facts_marker(artifact_type, artifact_name, expected):
    assert Core.is_invalid_facts_marker(FakeArtifact(artifact_type, artifact_name)) is expected


def test_is_invalid_facts_marker_ignores_version():
    """The API pins the marker to 1.0.0 today, but the version carries no meaning."""

    class Versioned(FakeArtifact):
        version = "9.9.9"

    assert Core.is_invalid_facts_marker(
        Versioned(INVALID_FACTS_MARKER_TYPE, INVALID_FACTS_MARKER_NAME)
    )


# --- Filtering: full-scan SBOM path -------------------------------------------------------


def test_get_sbom_data_drops_marker(core, data_dir, load_json, caplog):
    """The marker never reaches packages built from a full scan's SBOM."""
    json_data = load_json(data_dir / "fullscans" / "head_scan" / "stream_scan.json")
    artifacts = copy.deepcopy(json_data["artifacts"])
    artifacts["invalid-facts-1"] = make_marker_artifact()
    core.sdk.fullscans.stream.side_effect = None
    core.sdk.fullscans.stream.return_value = FullScanStreamResponse.from_dict({
        "success": True,
        "status": 200,
        "artifacts": artifacts,
    })

    with caplog.at_level("WARNING"):
        result = core.get_sbom_data("head")

    assert "invalid-facts-1" not in result
    assert len(result) == len(json_data["artifacts"])
    assert "could not parse the uploaded .socket.facts.json" in caplog.text


def test_get_sbom_data_does_not_warn_without_marker(core, caplog):
    """A clean scan produces no facts-parse warning."""
    with caplog.at_level("WARNING"):
        core.get_sbom_data("head")

    assert "could not parse the uploaded .socket.facts.json" not in caplog.text


# --- Filtering: diff path (the flow that posts the PR comment) ---------------------------


def _diff_response_with_marker(data_dir, load_json, buckets=("added",)):
    json_data = load_json(data_dir / "fullscans" / "diff" / "stream_diff.json")
    artifacts = copy.deepcopy(json_data["data"]["artifacts"])
    for index, bucket in enumerate(buckets):
        artifacts[bucket].append(
            make_marker_artifact(diff_type=bucket, artifact_id=f"invalid-facts-{index}")
        )
    return StreamDiffResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "data": {**json_data["data"], "artifacts": artifacts},
    })


def test_diff_drops_marker_from_added_packages(core, data_dir, load_json, caplog):
    """An added marker yields no package and no blocking alert.

    Left in, it surfaces as `NEW blocking issues: 1` and a PR comment for a package the
    developer never added.
    """
    core.sdk.fullscans.stream_diff.side_effect = None
    core.sdk.fullscans.stream_diff.return_value = _diff_response_with_marker(
        data_dir, load_json
    )
    # Force the legacy streaming diff so the fixture above is the artifact source.
    core.sdk.diffscans.create_from_ids.side_effect = Exception("diff-scans unavailable")

    with caplog.at_level("WARNING"):
        added, removed, packages = core.get_added_and_removed_packages("head", "new")

    assert not any(
        pkg.name == INVALID_FACTS_MARKER_NAME
        for pkg in list(added.values()) + list(removed.values()) + list(packages.values())
    )
    diff = core.create_diff_report(added, removed)
    assert not any(alert.pkg_name == INVALID_FACTS_MARKER_NAME for alert in diff.new_alerts)
    assert "could not parse the uploaded .socket.facts.json" in caplog.text


def test_diff_drops_marker_from_every_bucket(core, data_dir, load_json):
    """Removed and unchanged markers are dropped too.

    An unchanged marker would otherwise become an existing violation under
    --strict-blocking, and a removed one would show up as a resolved alert.
    """
    core.sdk.fullscans.stream_diff.side_effect = None
    core.sdk.fullscans.stream_diff.return_value = _diff_response_with_marker(
        data_dir, load_json, buckets=("added", "removed", "unchanged")
    )
    core.sdk.diffscans.create_from_ids.side_effect = Exception("diff-scans unavailable")

    added, removed, packages = core.get_added_and_removed_packages("head", "new")

    assert not any(
        pkg.name == INVALID_FACTS_MARKER_NAME
        for pkg in list(added.values()) + list(removed.values()) + list(packages.values())
    )


def test_diff_artifact_counts_exclude_marker(core, data_dir, load_json, caplog):
    """The logged counts describe what the CLI reports on, not the raw API response.

    "Added: 1" in a run whose only added artifact was the marker sends whoever reads the log
    looking for a package that was never there.
    """
    core.sdk.fullscans.stream_diff.side_effect = None
    core.sdk.fullscans.stream_diff.return_value = _diff_response_with_marker(
        data_dir, load_json
    )
    core.sdk.diffscans.create_from_ids.side_effect = Exception("diff-scans unavailable")
    unfiltered_added = len(
        load_json(data_dir / "fullscans" / "diff" / "stream_diff.json")["data"]["artifacts"][
            "added"
        ]
    )

    with caplog.at_level("INFO"):
        core.get_added_and_removed_packages("head", "new")

    assert f"Added: {unfiltered_added}" in caplog.text
    assert f"Added: {unfiltered_added + 1}" not in caplog.text


def test_diff_keeps_real_packages(core, data_dir, load_json):
    """Filtering the marker leaves genuine packages untouched."""
    core.sdk.fullscans.stream_diff.side_effect = None
    unfiltered = load_json(data_dir / "fullscans" / "diff" / "stream_diff.json")
    core.sdk.fullscans.stream_diff.return_value = _diff_response_with_marker(
        data_dir, load_json
    )
    core.sdk.diffscans.create_from_ids.side_effect = Exception("diff-scans unavailable")

    added, removed, _ = core.get_added_and_removed_packages("head", "new")

    expected_added = len(unfiltered["data"]["artifacts"]["added"]) + len(
        unfiltered["data"]["artifacts"]["updated"]
    )
    expected_removed = len(unfiltered["data"]["artifacts"]["removed"]) + len(
        unfiltered["data"]["artifacts"]["replaced"]
    )
    assert len(added) == expected_added
    assert len(removed) == expected_removed
