"""FOSSA-compat output shaping for `--legal-format fossa`.

Builds two artifacts whose top-level shapes mirror real FOSSA pipeline outputs:

  fossa-analyze.json  — wrapper of {project, vulnerability, licensing, quality},
                        where `project` is the raw `fossa analyze --json` shape and
                        the three arrays are FOSSA /api/v2/issues-shaped items.
  fossa-sbom.json     — `fossa report --json attribution` shape: 5 top-level keys
                        (copyrightsByLicense, deepDependencies, directDependencies,
                        licenses, project).

Fields without a Socket data source are emitted as documented defaults:

  vulnerability[]:
    epss               -> {score: None, percentile: None}
    cvssVector         -> None
    exploitability     -> None
    cveStatus          -> None
    published          -> None
    containerLayers    -> {base: 0, other: 0}
    customRiskScore    -> None
    remediation.partialFixDistance, completeFixDistance -> None  (semver-distance TBD)
    remediation.partialFix, completeFix                 -> same Socket fix version
                                                           (Socket has no partial/complete distinction)
    projects[].scannedAt, analyzedAt, firstFoundAt      -> None

  dependencies[] (SBOM):
    description, downloadUrl, projectUrl -> ""
    hash, isGolang                       -> None  (always null in real FOSSA samples)
    notes, otherLicenses                 -> []

  Top-level SBOM:
    copyrightsByLicense -> {}  (would require parsing attribText for `Copyright (c)` lines)
    licenses            -> {}  (would require bundling SPDX license body texts)
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue, Package

LICENSE_ALERT_TYPES = {"licenseSpdxDisj"}
QUALITY_ALERT_PREFIXES = ("risk", "quality", "outdated", "unmaintained")


def _ecosystem_to_package_manager(ecosystem: Optional[str]) -> str:
    mapping = {
        "pypi": "pip",
        "npm": "npm",
        "maven": "maven",
        "nuget": "nuget",
        "gem": "gem",
        "golang": "go",
        "cargo": "cargo",
    }
    if not ecosystem:
        return "unknown"
    return mapping.get(ecosystem, ecosystem)


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _build_project_metadata(diff_report: Diff, config: CliConfig) -> dict[str, Any]:
    repo = getattr(config, "repo", None) or "socket-default-repo"
    branch = getattr(config, "branch", None) or "socket-default-branch"
    revision = getattr(diff_report, "id", None) or getattr(diff_report, "new_scan_id", None) or "unknown-revision"
    report_url = getattr(diff_report, "report_url", None) or getattr(diff_report, "diff_url", None)
    return {
        "branch": branch,
        "id": f"{repo}${revision}",
        "project": repo,
        "projectId": repo,
        "revision": revision,
        "url": report_url,
    }


def _build_source_metadata(issue: Issue, package: Optional[Package]) -> dict[str, Any]:
    package_type = _ecosystem_to_package_manager(
        getattr(package, "type", None) or getattr(issue, "pkg_type", None)
    )
    package_name = getattr(package, "name", None) or getattr(issue, "pkg_name", None)
    package_version = getattr(package, "version", None) or getattr(issue, "pkg_version", None)
    package_url = getattr(package, "url", None) or getattr(issue, "url", None)
    return {
        "id": f"{package_type}+{package_name}${package_version}",
        "name": package_name,
        "url": package_url,
        "version": package_version,
        "packageManager": package_type,
    }


def _build_depths(package: Optional[Package]) -> dict[str, int]:
    is_direct = bool(getattr(package, "direct", False))
    return {
        "direct": 1 if is_direct else 0,
        "deep": 0 if is_direct else 1,
    }


def _build_statuses(issue: Issue) -> dict[str, int]:
    is_ignored = bool(getattr(issue, "ignore", False))
    return {
        "active": 0 if is_ignored else 1,
        "ignored": 1 if is_ignored else 0,
    }


def _build_projects_entry(project: dict[str, Any], package: Optional[Package]) -> list[dict[str, Any]]:
    is_direct = bool(getattr(package, "direct", False))
    return [{
        "id": project["projectId"],
        "status": "active",
        "depth": 1 if is_direct else 2,
        "title": project["project"],
        "scannedAt": None,
        "analyzedAt": None,
        "url": project["url"],
        "firstFoundAt": None,
        "defaultBranch": project["branch"],
        "latest": True,
        "revisionId": f"{project['projectId']}${project['revision']}",
        "revisionScanId": project["revision"],
    }]


def _extract_cve(props: dict[str, Any]) -> Optional[str]:
    cve = _first_non_empty(props.get("cveId"), props.get("cve"))
    if isinstance(cve, list):
        return cve[0] if cve else None
    return cve


def _extract_float(*values: Any) -> Optional[float]:
    value = _first_non_empty(*values)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_string_list(*values: Any) -> list[str]:
    items = _listify(_first_non_empty(*values))
    output = []
    for item in items:
        if isinstance(item, str) and item:
            output.append(item)
    return output


def _build_remediation(props: dict[str, Any]) -> dict[str, Any]:
    fix = _first_non_empty(
        props.get("firstPatchedVersionIdentifier"),
        props.get("partialFix"),
        props.get("completeFix"),
        props.get("fixedVersion"),
        props.get("fixed_version"),
        props.get("patchedVersion"),
        props.get("patched_version"),
    )
    return {
        "partialFix": fix,
        "partialFixDistance": props.get("partialFixDistance"),
        "completeFix": fix,
        "completeFixDistance": props.get("completeFixDistance"),
    }


def _build_epss(props: dict[str, Any]) -> dict[str, Any]:
    score = _extract_float(props.get("epssScore"), props.get("epss_score"))
    percentile = _extract_float(props.get("epssPercentile"), props.get("epss_percentile"))
    return {
        "score": score,
        "percentile": percentile,
    }


def _build_metrics(props: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = props.get("metrics")
    if isinstance(metrics, list):
        return metrics

    metric_map = [
        ("Attack Vector", props.get("attackVector")),
        ("Attack Complexity", props.get("attackComplexity")),
        ("Privileges Required", props.get("privilegesRequired")),
        ("User Interaction", props.get("userInteraction")),
        ("Scope", props.get("scope")),
        ("Confidentiality Impact", props.get("confidentialityImpact")),
        ("Integrity Impact", props.get("integrityImpact")),
        ("Availability Impact", props.get("availabilityImpact")),
    ]
    return [
        {"name": name, "value": value}
        for name, value in metric_map
        if value not in (None, "")
    ]


def _extract_references(issue: Issue, props: dict[str, Any]) -> list[str]:
    references = _listify(props.get("references"))
    if props.get("url"):
        references.append(props["url"])
    if getattr(issue, "url", None):
        references.append(issue.url)
    deduped = []
    seen = set()
    for reference in references:
        if not isinstance(reference, str) or not reference:
            continue
        if reference in seen:
            continue
        seen.add(reference)
        deduped.append(reference)
    return deduped


def _build_vulnerability_entry(
    issue: Issue, package: Optional[Package], project: dict[str, Any], index: int
) -> dict[str, Any]:
    props = getattr(issue, "props", {}) or {}
    return {
        "id": props.get("id") or f"socket-vulnerability-{index}",
        "type": "vulnerability",
        "createdAt": props.get("createdAt"),
        "source": _build_source_metadata(issue, package),
        "depths": _build_depths(package),
        "containerLayers": {"base": 0, "other": 0},
        "statuses": _build_statuses(issue),
        "projects": _build_projects_entry(project, package),
        "url": getattr(issue, "url", None) or project["url"],
        "vulnId": _first_non_empty(props.get("ghsaId"), props.get("cveId"), issue.key, f"socket-vuln-{index}"),
        "title": getattr(issue, "title", None),
        "cve": _extract_cve(props),
        "cvss": _extract_float(props.get("cvssScore"), props.get("cvss")),
        "severity": getattr(issue, "severity", "unknown"),
        "details": _first_non_empty(getattr(issue, "description", None), props.get("overview"), props.get("note")),
        "remediation": _build_remediation(props),
        "metrics": _build_metrics(props),
        "cveStatus": props.get("cveStatus"),
        "cwes": _extract_string_list(props.get("cwes"), props.get("cwe")),
        "published": props.get("published"),
        "affectedVersionRanges": _extract_string_list(
            props.get("affectedVersionRanges"),
            props.get("vulnerableVersionRange"),
            props.get("affected_versions"),
        ),
        "patchedVersionRanges": _extract_string_list(
            props.get("patchedVersionRanges"),
            props.get("firstPatchedVersionIdentifier"),
            props.get("patched_versions"),
        ),
        "references": _extract_references(issue, props),
        "cvssVector": props.get("cvssVector"),
        "exploitability": props.get("exploitability"),
        "epss": _build_epss(props),
        "cpes": _extract_string_list(props.get("cpes")),
        "customRiskScore": None,
    }


def _build_licensing_entry(
    issue: Issue, package: Optional[Package], project: dict[str, Any], index: int
) -> dict[str, Any]:
    props = getattr(issue, "props", {}) or {}
    package_license = getattr(package, "license", None)
    issue_type = "policy_conflict"
    if not package_license:
        issue_type = "unlicensed_dependency"
    elif getattr(issue, "type", None) not in LICENSE_ALERT_TYPES:
        issue_type = "policy_flag"
    return {
        "id": props.get("id") or f"socket-licensing-{index}",
        "type": issue_type,
        "createdAt": props.get("createdAt"),
        "source": _build_source_metadata(issue, package),
        "depths": _build_depths(package),
        "statuses": _build_statuses(issue),
        "projects": _build_projects_entry(project, package),
        "url": getattr(issue, "url", None) or project["url"],
        "title": getattr(issue, "title", None) or "License Policy Violation",
        "details": _first_non_empty(getattr(issue, "description", None), props.get("note"), package_license),
        "license": package_license,
        "identifiedLicense": package_license,
        "references": _extract_references(issue, props),
    }


def _build_quality_entry(
    issue: Issue, package: Optional[Package], project: dict[str, Any], index: int
) -> dict[str, Any]:
    props = getattr(issue, "props", {}) or {}
    return {
        "id": props.get("id") or f"socket-quality-{index}",
        "type": getattr(issue, "type", None) or "quality_issue",
        "createdAt": props.get("createdAt"),
        "source": _build_source_metadata(issue, package),
        "depths": _build_depths(package),
        "statuses": _build_statuses(issue),
        "projects": _build_projects_entry(project, package),
        "url": getattr(issue, "url", None) or project["url"],
        "title": getattr(issue, "title", None),
        "details": _first_non_empty(getattr(issue, "description", None), props.get("note")),
        "references": _extract_references(issue, props),
    }


def _iter_selected_issues(diff_report: Diff, config: CliConfig) -> Iterable[Issue]:
    yield from getattr(diff_report, "new_alerts", []) or []
    if getattr(config, "strict_blocking", False):
        yield from getattr(diff_report, "unchanged_alerts", []) or []


def _classify_issue(issue: Issue) -> str:
    issue_type = (getattr(issue, "type", "") or "").lower()
    category = (getattr(issue, "category", "") or "").lower()
    if issue_type in LICENSE_ALERT_TYPES or "license" in issue_type or category == "licensing":
        return "licensing"
    if category == "quality" or issue_type.startswith(QUALITY_ALERT_PREFIXES):
        return "quality"
    return "vulnerability"


def build_fossa_report_payload(diff_report: Diff, config: CliConfig) -> dict[str, Any]:
    project = _build_project_metadata(diff_report, config)
    package_lookup = getattr(diff_report, "packages", {}) or {}
    vulnerabilities = []
    licensing = []
    quality = []

    for index, issue in enumerate(_iter_selected_issues(diff_report, config), start=1):
        package = package_lookup.get(getattr(issue, "pkg_id", "")) if package_lookup else None
        category = _classify_issue(issue)
        if category == "licensing":
            licensing.append(_build_licensing_entry(issue, package, project, index))
        elif category == "quality":
            quality.append(_build_quality_entry(issue, package, project, index))
        else:
            vulnerabilities.append(_build_vulnerability_entry(issue, package, project, index))

    return {
        "project": project,
        "vulnerability": vulnerabilities,
        "licensing": licensing,
        "quality": quality,
    }


def _build_attribution_project(diff_report: Diff, config: CliConfig) -> dict[str, Any]:
    repo = getattr(config, "repo", None) or "socket-default-repo"
    revision = (
        getattr(diff_report, "id", None)
        or getattr(diff_report, "new_scan_id", None)
        or "unknown-revision"
    )
    return {"name": repo, "revision": revision}


def _build_dependency_licenses(package: Package) -> list[dict[str, str]]:
    """Build the `licenses[]` array: prefer licenseAttrib entries (full attribution text),
    fall back to a single name-only entry from declared license, else empty.
    """
    attribs = getattr(package, "licenseAttrib", None) or []
    licenses = []
    for attrib in attribs:
        attrib_text = attrib.get("attribText", "") if isinstance(attrib, dict) else getattr(attrib, "attribText", "")
        attrib_data = attrib.get("attribData", []) if isinstance(attrib, dict) else getattr(attrib, "attribData", [])
        spdx = ""
        if attrib_data:
            first = attrib_data[0]
            spdx = first.get("spdxExpr", "") if isinstance(first, dict) else getattr(first, "spdxExpr", "")
        if attrib_text or spdx:
            licenses.append({"attribution": attrib_text or "", "name": spdx or getattr(package, "license", "") or ""})
    if licenses:
        return licenses
    declared = getattr(package, "license", None)
    if declared:
        return [{"attribution": "", "name": declared}]
    return []


def _build_dependency_entry(package: Package, dependency_paths: list[str]) -> dict[str, Any]:
    return {
        "authors": list(getattr(package, "author", []) or []),
        "dependencyPaths": list(dependency_paths),
        "description": "",
        "downloadUrl": "",
        "hash": None,
        "isGolang": None,
        "licenses": _build_dependency_licenses(package),
        "notes": [],
        "otherLicenses": [],
        "package": package.name,
        "projectUrl": "",
        "source": _ecosystem_to_package_manager(package.type),
        "title": package.name,
        "version": package.version,
    }


def _compute_dependency_paths(package: Package, package_lookup: dict[str, Package]) -> list[str]:
    if bool(getattr(package, "direct", False)):
        return [package.name]
    ancestors = getattr(package, "topLevelAncestors", None) or []
    paths = []
    for ancestor_id in ancestors:
        ancestor = package_lookup.get(ancestor_id)
        if ancestor and getattr(ancestor, "name", None):
            paths.append(f"{ancestor.name} > {package.name}")
    if not paths:
        return [package.name]
    return paths


def _partition_dependencies(packages: list[Package]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    direct: list[dict[str, Any]] = []
    deep: list[dict[str, Any]] = []
    package_lookup = {getattr(p, "id", None): p for p in packages if getattr(p, "id", None)}
    for package in packages:
        paths = _compute_dependency_paths(package, package_lookup)
        entry = _build_dependency_entry(package, paths)
        if bool(getattr(package, "direct", False)):
            direct.append(entry)
        else:
            deep.append(entry)
    return direct, deep


def build_fossa_attribution_payload(diff_report: Diff, config: CliConfig) -> dict[str, Any]:
    packages = list((getattr(diff_report, "packages", {}) or {}).values())
    direct, deep = _partition_dependencies(packages)
    return {
        "copyrightsByLicense": {},
        "deepDependencies": deep,
        "directDependencies": direct,
        "licenses": {},
        "project": _build_attribution_project(diff_report, config),
    }
