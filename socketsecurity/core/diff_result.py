from dataclasses import dataclass
from typing import Dict, Optional

from socketdev.fullscans import DiffArtifacts

from socketsecurity.core.classes import Package


@dataclass
class DiffScanResult:
    artifacts: DiffArtifacts
    diff_scan_id: Optional[str]
    diff_url: Optional[str] = None
    old_scan_url: Optional[str] = None
    new_scan_url: Optional[str] = None


@dataclass
class PackageComparisonResult:
    added_packages: Dict[str, Package]
    removed_packages: Dict[str, Package]
    packages: Dict[str, Package]
    diff_scan_id: Optional[str]
    diff_url: Optional[str] = None
    old_scan_url: Optional[str] = None
    new_scan_url: Optional[str] = None


def normalize_report_url(value: object) -> Optional[str]:
    if isinstance(value, str) and value:
        return value
    return None


def matching_full_scan_url(value: object, scan_id: str) -> Optional[str]:
    if not isinstance(value, dict) or value.get("id") != scan_id:
        return None
    return normalize_report_url(value.get("html_url"))


def create_diff_scan_result(
    artifacts: Dict[str, object],
    diff_scan_id: Optional[str],
    *,
    diff_url: Optional[str] = None,
    old_scan_url: Optional[str] = None,
    new_scan_url: Optional[str] = None,
) -> DiffScanResult:
    return DiffScanResult(
        artifacts=DiffArtifacts.from_dict({
            key: artifacts.get(key) or []
            for key in ("added", "removed", "unchanged", "replaced", "updated")
        }),
        diff_scan_id=diff_scan_id,
        diff_url=diff_url,
        old_scan_url=old_scan_url,
        new_scan_url=new_scan_url,
    )
