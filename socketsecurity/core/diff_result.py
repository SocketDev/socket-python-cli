from dataclasses import dataclass
from typing import Dict, Optional

from socketdev.fullscans import DiffArtifacts

from socketsecurity.core.classes import Package


@dataclass
class DiffScanResult:
    artifacts: DiffArtifacts
    diff_scan_id: Optional[str]


@dataclass
class PackageComparisonResult:
    added_packages: Dict[str, Package]
    removed_packages: Dict[str, Package]
    packages: Dict[str, Package]
    diff_scan_id: Optional[str]


def create_diff_scan_result(
    artifacts: Dict[str, object], diff_scan_id: Optional[str]
) -> DiffScanResult:
    return DiffScanResult(
        artifacts=DiffArtifacts.from_dict({
            key: artifacts.get(key) or []
            for key in ("added", "removed", "unchanged", "replaced", "updated")
        }),
        diff_scan_id=diff_scan_id,
    )
