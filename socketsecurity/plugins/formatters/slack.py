"""Slack formatter for Socket Facts (reachability analysis) data."""

import logging
from typing import Dict, Any, List
from collections import defaultdict

logger = logging.getLogger(__name__)

# Severity display configuration
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
SEVERITY_EMOJI = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '⚪'
}


def _make_purl(component: Dict[str, Any]) -> str:
    """
    Construct a package URL (purl) from a component entry.
    
    Args:
        component: Component dictionary from socket facts
    
    Returns:
        Package URL string in format: pkg:type/namespace/name@version
    """
    pkg_type = component.get('type', '')
    namespace = component.get('namespace', '')
    name = component.get('name') or component.get('id', '')
    version = component.get('version', '')
    
    if not name:
        return ''
    
    # Construct purl - handle scoped packages (namespace with @)
    if namespace:
        # Percent-encode @ in namespace for purl spec compliance
        ns_encoded = namespace.replace('@', '%40')
        purl = f"pkg:{pkg_type}/{ns_encoded}/{name}"
    else:
        purl = f"pkg:{pkg_type}/{name}"
    
    if version:
        purl = f"{purl}@{version}"
    
    return purl


def _get_reachability_from_alert(alert: Dict[str, Any]) -> str:
    """
    Extract reachability status from an alert.
    
    Args:
        alert: Alert dictionary from component
    
    Returns:
        Reachability status: 'reachable', 'unreachable', 'unknown', or 'error'
    """
    props = alert.get('props', {}) or {}
    reachability = props.get('reachability', 'unknown')
    
    # Normalize to expected values
    if isinstance(reachability, str):
        return reachability.lower()
    
    return 'unknown'


def _get_trace_from_alert(alert: Dict[str, Any], max_length: int = 500) -> str:
    """
    Extract and format trace data from an alert.
    
    Args:
        alert: Alert dictionary from component
        max_length: Maximum length for trace output (truncate if longer)
    
    Returns:
        Formatted trace string
    """
    props = alert.get('props', {}) or {}
    trace_raw = props.get('trace', '')
    
    trace_str = ''
    if isinstance(trace_raw, list):
        trace_str = '\n'.join(str(item) for item in trace_raw)
    elif isinstance(trace_raw, str):
        trace_str = trace_raw
    
    # Truncate if too long
    if trace_str and len(trace_str) > max_length:
        trace_str = trace_str[:max_length] + '\n...'
    
    return trace_str


def _extract_alert_info(component: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract standardized information from an alert.
    
    Args:
        component: Component dictionary containing the alert
        alert: Alert dictionary
    
    Returns:
        Dictionary with standardized alert information
    """
    props = alert.get('props', {}) or {}
    severity = str(alert.get('severity') or props.get('severity') or '').lower()
    
    return {
        'cve_id': str(props.get('ghsaId') or props.get('cveId') or alert.get('title') or 'Unknown'),
        'severity': severity,
        'severity_order': SEVERITY_ORDER.get(severity, 4),
        'severity_emoji': SEVERITY_EMOJI.get(severity, '⚪'),
        'reachability': _get_reachability_from_alert(alert),
        'trace': _get_trace_from_alert(alert),
        'purl': str(props.get('purl') or _make_purl(component) or component.get('name') or '-')
    }


def format_socket_facts_for_slack(
    components: List[Dict[str, Any]], 
    max_blocks: int = 45,
    include_traces: bool = True
) -> List[Dict[str, Any]]:
    """
    Format socket facts components with alerts for Slack notification.
    
    This function processes vulnerability data from Socket's reachability analysis
    and formats it for display in Slack with smart block limiting.
    
    Slack has a 50 block limit. We use ~4 blocks for header/summary, leaving ~45 for findings.
    
    Prioritization (when space limited):
    1. Reachable vulnerabilities (all severities)
    2. Unknown/error reachability (critical/high only)
    3. Skip unreachable vulnerabilities
    
    Further filtering by severity:
    - Critical (always show if reachable)
    - High (show if space allows)
    - Medium (show if space allows)
    - Low (skip if space limited)
    
    Args:
        components: List of component dictionaries from socket facts JSON
        max_blocks: Maximum number of blocks for findings (default: 45, Slack limit is 50)
        include_traces: Whether to include trace data for reachable findings
    
    Returns:
        List of notification dictionaries with structured vulnerability data.
    
    Example:
        >>> components = socket_facts['components']
        >>> notifications = format_socket_facts_for_slack(components)
        >>> for notif in notifications:
        ...     send_to_slack(notif['title'], notif['vulnerabilities'])
    """
    # Group findings by PURL and reachability status
    purl_groups = defaultdict(lambda: {
        'reachable': [],
        'unknown': [],
        'error': [],
        'unreachable': []
    })
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    reachability_counts = {'reachable': 0, 'unknown': 0, 'error': 0, 'unreachable': 0}
    
    # Process all components and their alerts
    for component in components:
        alerts = component.get('alerts', [])
        
        for alert in alerts:
            alert_info = _extract_alert_info(component, alert)
            purl = alert_info['purl']
            reachability = alert_info['reachability']
            
            # Count by severity
            if alert_info['severity'] in severity_counts:
                severity_counts[alert_info['severity']] += 1
            
            # Count by reachability
            if reachability in reachability_counts:
                reachability_counts[reachability] += 1
            
            # Group by reachability status
            if reachability in purl_groups[purl]:
                purl_groups[purl][reachability].append(alert_info)
    
    # Sort findings within each group by severity (most severe first)
    for purl in purl_groups:
        for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
            purl_groups[purl][reach_type].sort(key=lambda x: x['severity_order'])
    
    # Build Slack message content
    if not purl_groups:
        return [{
            'title': 'Socket Reachability Analysis',
            'summary': "✅ No vulnerabilities found in reachability analysis.",
            'vulnerabilities': []
        }]
    
    # Calculate totals
    total_findings = sum(severity_counts.values())
    
    # Build summary
    summary = (
        f"🔴 Critical: {severity_counts['critical']} | "
        f"🟠 High: {severity_counts['high']} | "
        f"🟡 Medium: {severity_counts['medium']} | "
        f"⚪ Low: {severity_counts['low']}\n\n"
        f"🎯 Reachable: {reachability_counts['reachable']} | "
        f"✓ Unreachable: {reachability_counts['unreachable']}"
    )
    
    # Collect and prioritize vulnerabilities for display
    # Priority: reachable (all) > unknown/error (critical/high) > skip unreachable unless space
    vulnerabilities_to_show = []
    
    # First, add all reachable vulnerabilities (highest priority)
    for purl in purl_groups:
        for finding in purl_groups[purl]['reachable']:
            vulnerabilities_to_show.append({
                'purl': purl,
                'finding': finding,
                'reachability': 'reachable',
                'priority': (0, finding['severity_order'])  # (reachability_pri, severity_pri)
            })
    
    # Add unknown/error reachability (critical and high only)
    for purl in purl_groups:
        for finding in purl_groups[purl]['unknown']:
            if finding['severity'] in ['critical', 'high']:
                vulnerabilities_to_show.append({
                    'purl': purl,
                    'finding': finding,
                    'reachability': 'unknown',
                    'priority': (1, finding['severity_order'])
                })
        for finding in purl_groups[purl]['error']:
            if finding['severity'] in ['critical', 'high']:
                vulnerabilities_to_show.append({
                    'purl': purl,
                    'finding': finding,
                    'reachability': 'error',
                    'priority': (1, finding['severity_order'])
                })
    
    # Sort by priority (reachability first, then severity)
    vulnerabilities_to_show.sort(key=lambda x: x['priority'])
    
    # Limit to max_blocks (each vulnerability = 1 block)
    selected_vulnerabilities = vulnerabilities_to_show[:max_blocks]
    
    # Calculate what was omitted
    omitted_count = total_findings - len(selected_vulnerabilities)
    omitted_unreachable = reachability_counts['unreachable']
    omitted_low = severity_counts['low'] - sum(1 for v in selected_vulnerabilities if v['finding']['severity'] == 'low')
    
    return [{
        'title': 'Socket Reachability Analysis',
        'summary': summary,
        'total_findings': total_findings,
        'vulnerabilities': selected_vulnerabilities,
        'omitted_count': omitted_count,
        'omitted_unreachable': omitted_unreachable,
        'omitted_low': omitted_low,
        'include_traces': include_traces
    }]
