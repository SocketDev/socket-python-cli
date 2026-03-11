import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.helper.socket_facts_loader import (
    convert_to_alerts,
    get_components_with_vulnerabilities,
    load_socket_facts,
)
from socketsecurity.core.messages import Messages


def select_diff_alerts(diff: Diff, strict_blocking: bool = False) -> List[Issue]:
    """Select diff alerts for output rendering.

    In strict blocking mode, include unchanged alerts so rendered output aligns
    with pass/fail policy evaluation.
    """
    selected = list(getattr(diff, "new_alerts", []) or [])
    if strict_blocking:
        selected.extend(getattr(diff, "unchanged_alerts", []) or [])
    return selected


def clone_diff_with_selected_alerts(diff: Diff, selected_alerts: List[Issue]) -> Diff:
    """Clone a diff object while replacing new_alerts with selected alerts."""
    selected_diff = Diff(
        new_alerts=selected_alerts,
        unchanged_alerts=[],
        removed_alerts=[],
        diff_url=getattr(diff, "diff_url", ""),
        new_packages=getattr(diff, "new_packages", []),
        removed_packages=getattr(diff, "removed_packages", []),
        packages=getattr(diff, "packages", {}),
    )
    selected_diff.id = getattr(diff, "id", "")
    selected_diff.report_url = getattr(diff, "report_url", "")
    selected_diff.new_scan_id = getattr(diff, "new_scan_id", "")
    return selected_diff


def load_components_with_alerts(
    target_path: Optional[str],
    reach_output_file: Optional[str],
) -> Optional[List[Dict[str, Any]]]:
    facts_file = reach_output_file or ".socket.facts.json"
    facts_file_path = str(Path(target_path or ".") / facts_file)
    facts_data = load_socket_facts(facts_file_path)
    if not facts_data:
        return None

    components = get_components_with_vulnerabilities(facts_data)
    return convert_to_alerts(components)


def _normalize_purl(purl: str) -> str:
    if not purl:
        return ""
    normalized = purl.strip().lower().replace("%40", "@")
    if normalized.startswith("pkg:"):
        normalized = normalized[4:]
    return normalized


def _normalize_vuln_id(vuln_id: str) -> str:
    if not vuln_id:
        return ""
    return vuln_id.strip().upper()


def _normalize_pkg_key(pkg_type: str, pkg_name: str, pkg_version: str) -> Tuple[str, str, str]:
    return (
        (pkg_type or "").strip().lower(),
        (pkg_name or "").strip().lower(),
        (pkg_version or "").strip().lower(),
    )


def _extract_issue_vuln_ids(issue: Issue) -> Set[str]:
    ids: Set[str] = set()
    props = getattr(issue, "props", None) or {}
    for key in ("ghsaId", "ghsa_id", "cveId", "cve_id"):
        value = props.get(key)
        if isinstance(value, str) and value.strip():
            ids.add(_normalize_vuln_id(value))
    return ids


def _is_potentially_reachable(reachability: str, undeterminable: bool = False) -> bool:
    normalized = Messages._normalize_reachability(reachability)
    potential_states = {"unknown", "error", "maybe_reachable", "potentially_reachable"}
    return normalized in potential_states or undeterminable


def _matches_selector(states: Set[str], selector: str) -> bool:
    selected = (selector or "all").strip().lower()
    if selected == "all":
        return True
    if not states:
        return False
    if selected == "reachable":
        return "reachable" in states
    if selected == "potentially":
        return any(_is_potentially_reachable(state) for state in states)
    if selected == "reachable-or-potentially":
        return "reachable" in states or any(_is_potentially_reachable(state) for state in states)
    return True


def _build_reachability_index(
    components_with_alerts: Optional[List[Dict[str, Any]]],
) -> Optional[Tuple[Dict[str, Dict[str, Set[str]]], Dict[Tuple[str, str, str], Dict[str, Set[str]]]]]:
    if not components_with_alerts:
        return None

    by_purl: Dict[str, Dict[str, Set[str]]] = {}
    by_pkg: Dict[Tuple[str, str, str], Dict[str, Set[str]]] = {}

    for component in components_with_alerts:
        component_alerts = component.get("alerts", [])
        pkg_type = component.get("type", "")
        pkg_version = component.get("version", "")
        namespace = (component.get("namespace") or "").strip()
        name = (component.get("name") or component.get("id") or "").strip()

        pkg_names: Set[str] = {name}
        if namespace:
            pkg_names.add(f"{namespace}/{name}")

        for alert in component_alerts:
            props = alert.get("props", {}) or {}
            reachability = Messages._normalize_reachability(props.get("reachability", "unknown"))
            vuln_ids = {
                _normalize_vuln_id(props.get("ghsaId", "")),
                _normalize_vuln_id(props.get("cveId", "")),
            }
            vuln_ids = {v for v in vuln_ids if v}
            purl = _normalize_purl(props.get("purl", ""))

            def _add(container: Dict[Any, Dict[str, Set[str]]], key: Any) -> None:
                if key not in container:
                    container[key] = {}
                vuln_key = next(iter(vuln_ids)) if len(vuln_ids) == 1 else "*"
                if vuln_key not in container[key]:
                    container[key][vuln_key] = set()
                container[key][vuln_key].add(reachability)
                if vuln_ids and vuln_key == "*":
                    for vuln_id in vuln_ids:
                        if vuln_id not in container[key]:
                            container[key][vuln_id] = set()
                        container[key][vuln_id].add(reachability)
                if not vuln_ids:
                    if "*" not in container[key]:
                        container[key]["*"] = set()
                    container[key]["*"].add(reachability)

            if purl:
                _add(by_purl, purl)

            for pkg_name in pkg_names:
                pkg_key = _normalize_pkg_key(pkg_type, pkg_name, pkg_version)
                _add(by_pkg, pkg_key)

    return by_purl, by_pkg


def _alert_reachability_states(
    alert: Issue,
    by_purl: Dict[str, Dict[str, Set[str]]],
    by_pkg: Dict[Tuple[str, str, str], Dict[str, Set[str]]],
) -> Set[str]:
    states: Set[str] = set()
    alert_ids = _extract_issue_vuln_ids(alert)
    alert_purl = _normalize_purl(getattr(alert, "purl", ""))
    pkg_key = _normalize_pkg_key(
        getattr(alert, "pkg_type", ""),
        getattr(alert, "pkg_name", ""),
        getattr(alert, "pkg_version", ""),
    )

    def _collect(index: Dict[Any, Dict[str, Set[str]]], key: Any) -> Set[str]:
        found: Set[str] = set()
        mapping = index.get(key, {})
        if not mapping:
            return found

        if "*" in mapping:
            found.update(mapping["*"])

        if alert_ids:
            for alert_id in alert_ids:
                if alert_id in mapping:
                    found.update(mapping[alert_id])
        else:
            for value in mapping.values():
                found.update(value)
        return found

    if alert_purl:
        states.update(_collect(by_purl, alert_purl))
    states.update(_collect(by_pkg, pkg_key))
    return states


def filter_alerts_by_reachability(
    alerts: List[Issue],
    selector: str,
    target_path: Optional[str],
    reach_output_file: Optional[str],
    logger: Optional[logging.Logger] = None,
    fallback_to_blocking_for_reachable: bool = True,
) -> List[Issue]:
    """
    Filter issue alerts by reachability selector using .socket.facts.json data.

    If facts data is unavailable and selector is `reachable`, optionally falls back
    to `issue.error == True` for backward compatibility.
    """
    normalized_selector = (selector or "all").strip().lower()
    if normalized_selector == "all":
        return list(alerts)

    components_with_alerts = load_components_with_alerts(target_path, reach_output_file)
    reachability_index = _build_reachability_index(components_with_alerts)
    if not reachability_index:
        if logger:
            logger.warning("Unable to load reachability facts for selector '%s'", normalized_selector)
        if normalized_selector == "reachable" and fallback_to_blocking_for_reachable:
            return [a for a in alerts if getattr(a, "error", False)]
        return []

    by_purl, by_pkg = reachability_index
    filtered: List[Issue] = []
    for alert in alerts:
        states = _alert_reachability_states(alert, by_purl, by_pkg)
        if _matches_selector(states, normalized_selector):
            filtered.append(alert)
    return filtered
