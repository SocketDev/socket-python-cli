import logging
import requests
from socketsecurity.config import CliConfig
from .base import Plugin
from socketsecurity.core.classes import Diff
from socketsecurity.core.messages import Messages
from socketsecurity.core.helper.socket_facts_loader import (
    load_socket_facts,
    get_components_with_vulnerabilities,
    convert_to_alerts
)
from socketsecurity.plugins.formatters.slack import format_socket_facts_for_slack

logger = logging.getLogger(__name__)


class SlackPlugin(Plugin):
    @staticmethod
    def get_name():
        return "slack"

    def send(self, diff, config: CliConfig):
        if not self.config.get("enabled", False):
            if config.enable_debug:
                logger.debug("Slack plugin is disabled - skipping webhook notification")
            return
        if not self.config.get("url"):
            logger.warning("Slack webhook URL not configured.")
            if config.enable_debug:
                logger.debug("Slack webhook URL is missing from configuration")
            return
        
        # Normalize URL configuration to list of dicts
        url_configs = self._normalize_url_config(self.config.get("url"))
        
        if not url_configs:
            logger.warning("No valid Slack webhook URLs configured.")
            return

        logger.debug("Slack Plugin Enabled")
        logger.debug("Alert levels: %s", self.config.get("levels"))

        # Get url_configs parameter (filtering configuration)
        webhook_configs = self.config.get("url_configs", {})
        
        # Validate that all URLs have corresponding configs
        valid_webhooks = []
        for url_config in url_configs:
            name = url_config["name"]
            if name not in webhook_configs:
                logger.warning(f"No url_configs entry found for webhook '{name}'. This webhook will be disabled.")
                continue
            valid_webhooks.append(url_config)
        
        if not valid_webhooks:
            logger.warning("No valid Slack webhooks with configurations. All webhooks disabled.")
            return
        
        # Get repo name from config
        repo_name = config.repo or ""
        
        # Handle reachability data if --reach is enabled
        if config.reach:
            self._send_reachability_alerts(valid_webhooks, webhook_configs, repo_name, config, diff)
        
        # Handle diff alerts (if any)
        if not diff.new_alerts:
            logger.debug("No new diff alerts to notify via Slack.")
        else:
            # Send to each configured webhook with filtering
            for url_config in valid_webhooks:
                url = url_config["url"]
                name = url_config["name"]
                webhook_config = webhook_configs[name]
                
                # Filter alerts based on webhook config
                # When --reach is used, reachability_alerts_only applies to diff alerts
                filtered_alerts = self._filter_alerts(
                    diff.new_alerts, 
                    webhook_config, 
                    repo_name, 
                    config,
                    is_reachability_data=False,
                    apply_reachability_only_filter=config.reach
                )
                
                if not filtered_alerts:
                    logger.debug(f"No diff alerts match filter criteria for webhook '{name}'. Skipping.")
                    continue
                
                # Create a temporary diff object with filtered alerts for message creation
                filtered_diff = Diff(
                    new_alerts=filtered_alerts,
                    diff_url=getattr(diff, "diff_url", ""),
                    new_packages=getattr(diff, "new_packages", []),
                    removed_packages=getattr(diff, "removed_packages", []),
                    packages=getattr(diff, "packages", {})
                )
                
                message = self.create_slack_blocks_from_diff(filtered_diff, config)
                
                logger.debug(f"Sending diff alerts message to {name} ({url})")
                
                if config.enable_debug:
                    logger.debug(f"Slack webhook URL: {url}")
                    logger.debug(f"Slack webhook name: {name}")
                    logger.debug(f"Total diff alerts: {len(diff.new_alerts)}, Filtered alerts: {len(filtered_alerts)}")
                    logger.debug(f"Message blocks count: {len(message)}")
                
                response = requests.post(
                    url,
                    json={"blocks": message}
                )

                if response.status_code >= 400:
                    logger.error("Slack error for %s: %s - %s", name, response.status_code, response.text)
                elif config.enable_debug:
                    logger.debug(f"Slack webhook response for {name}: {response.status_code}")

    def _filter_alerts(
        self, 
        alerts: list, 
        webhook_config: dict, 
        repo_name: str, 
        config: CliConfig,
        is_reachability_data: bool = False,
        apply_reachability_only_filter: bool = False
    ) -> list:
        """
        Filter alerts based on webhook configuration.
        
        Empty lists or missing keys mean no filtering for that criteria:
        - repos: [] or missing → all repos allowed
        - alert_types: [] or missing → no alert_type filtering
        - severities: [] or missing → no severity filtering  
        - reachability_alerts_only: missing → defaults to False
        
        Args:
            alerts: List of Issue objects to filter
            webhook_config: Config dict with optional keys: repos, alert_types, severities, reachability_alerts_only
            repo_name: Current repository name from config
            config: CliConfig object
            is_reachability_data: If True, only apply severities filter (for .socket.facts.json data)
            apply_reachability_only_filter: If True, apply reachability_alerts_only filter (only when --reach is used)
        
        Returns:
            Filtered list of alerts matching the criteria
        """
        filtered = []
        
        # Extract filter configs (empty list/False means no filtering)
        repos_filter = webhook_config.get("repos", [])
        alert_types = webhook_config.get("alert_types", [])
        severities = webhook_config.get("severities", [])
        reachability_only = webhook_config.get("reachability_alerts_only", False)
        
        if config.enable_debug:
            logger.debug(f"Filtering {'reachability' if is_reachability_data else 'diff'} alerts with: "
                        f"repos={repos_filter}, alert_types={alert_types}, "
                        f"severities={severities}, reachability_only={reachability_only}, "
                        f"apply_reachability_only={apply_reachability_only_filter}")
        
        for alert in alerts:
            # For reachability data, only apply severities filter
            if is_reachability_data:
                # Filter by severities only (empty list = all severities allowed)
                if severities:
                    alert_severity = getattr(alert, "severity", "")
                    if alert_severity not in severities:
                        continue
                filtered.append(alert)
                continue
            
            # For diff alerts, apply all filters
            # Filter by repos (empty list = all repos allowed)
            if repos_filter and repo_name not in repos_filter:
                continue
            
            # Filter by reachability_alerts_only (only when --reach is used)
            if apply_reachability_only_filter and reachability_only:
                # Only include alerts that have error=True (blocking issues)
                if not getattr(alert, "error", False):
                    continue
            
            # Filter by alert_types (overrides severity, empty list = no filtering)
            if alert_types:
                alert_type = getattr(alert, "type", "")
                if alert_type not in alert_types:
                    continue
            else:
                # Only apply severity filter if alert_types is not specified
                # Empty severities list = all severities allowed
                if severities:
                    alert_severity = getattr(alert, "severity", "")
                    if alert_severity not in severities:
                        continue
            
            filtered.append(alert)
        
        return filtered

    def _send_reachability_alerts(self, valid_webhooks: list, webhook_configs: dict, repo_name: str, config: CliConfig, diff=None):
        """
        Load and send reachability alerts from .socket.facts.json file.
        
        Args:
            valid_webhooks: List of validated webhook configurations
            webhook_configs: Dictionary of webhook configurations with filters
            repo_name: Current repository name
            config: CliConfig object
            diff: Diff object containing diff_url for report link
        """
        logger.debug("Loading reachability data from .socket.facts.json")
        
        # Load socket facts file
        facts_data = load_socket_facts(".socket.facts.json")
        
        if not facts_data:
            logger.debug("No .socket.facts.json file found or failed to load")
            return
        
        # Get components with vulnerabilities
        components_with_vulns = get_components_with_vulnerabilities(facts_data)
        
        if not components_with_vulns:
            logger.debug("No components with vulnerabilities found in .socket.facts.json")
            return
        
        # Convert to alerts format
        components_with_alerts = convert_to_alerts(components_with_vulns)
        
        if not components_with_alerts:
            logger.debug("No alerts generated from .socket.facts.json")
            return
        
        logger.debug(f"Found {len(components_with_alerts)} components with reachability alerts")
        
        # Send to each configured webhook with filtering
        for url_config in valid_webhooks:
            url = url_config["url"]
            name = url_config["name"]
            webhook_config = webhook_configs[name]
            
            # Filter components based on severities only (for reachability data)
            filtered_components = []
            for component in components_with_alerts:
                component_alerts = component.get('alerts', [])
                # Filter alerts using only severities
                filtered_component_alerts = self._filter_alerts(
                    component_alerts,
                    webhook_config,
                    repo_name,
                    config,
                    is_reachability_data=True
                )
                
                if filtered_component_alerts:
                    # Create a copy of component with only filtered alerts
                    filtered_component = component.copy()
                    filtered_component['alerts'] = filtered_component_alerts
                    filtered_components.append(filtered_component)
            
            if not filtered_components:
                logger.debug(f"No reachability alerts match filter criteria for webhook '{name}'. Skipping.")
                continue
            
            # Format for Slack using the formatter (max 45 blocks for findings + 5 for header/footer)
            slack_notifications = format_socket_facts_for_slack(
                filtered_components,
                max_blocks=45,
                include_traces=True
            )
            
            # Convert to Slack blocks format
            for notification in slack_notifications:
                blocks = self._create_reachability_slack_blocks_from_structured(
                    notification,
                    config,
                    diff
                )
                
                logger.debug(f"Sending reachability alerts message to {name} ({url})")
                
                if config.enable_debug:
                    logger.debug(f"Slack webhook URL: {url}")
                    logger.debug(f"Slack webhook name: {name}")
                    logger.debug(f"Reachability components: {len(filtered_components)}")
                    logger.debug(f"Message blocks count: {len(blocks)}")
                
                response = requests.post(
                    url,
                    json={"blocks": blocks}
                )
                
                if response.status_code >= 400:
                    logger.error("Slack error for %s: %s - %s", name, response.status_code, response.text)
                elif config.enable_debug:
                    logger.debug(f"Slack webhook response for {name}: {response.status_code}")
    
    def _create_reachability_slack_blocks_from_structured(self, notification: dict, config: CliConfig, diff=None) -> list:
        """
        Create Slack blocks from structured reachability notification data.
        Respects Slack's 50 block limit by prioritizing critical findings.
        
        Args:
            notification: Structured notification dict from format_socket_facts_for_slack
            config: CliConfig object
            diff: Diff object containing diff_url for report link
        
        Returns:
            List of Slack block dictionaries (max 50 blocks)
        """
        pr = getattr(config, "pr_number", None)
        sha = getattr(config, "commit_sha", None)
        diff_url = getattr(diff, "diff_url", "") if diff else ""
        
        title_part = ""
        if pr:
            title_part += f" for PR {pr}"
        if sha:
            title_part += f" - {sha[:8]}"
        
        # Header blocks (2 blocks)
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{notification['title']}*{title_part}"
                }
            },
            {"type": "divider"}
        ]
        
        # Summary block (2 blocks)
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": notification['summary']
            }
        })
        blocks.append({"type": "divider"})
        
        # Vulnerability blocks (1 block per vulnerability, max ~45)
        include_traces = notification.get('include_traces', True)
        for vuln in notification.get('vulnerabilities', []):
            finding = vuln['finding']
            reachability = vuln['reachability']
            
            # Reachability indicator
            reach_indicator = {
                'reachable': '🎯 *Reachable*',
                'unreachable': '✓ *Unreachable*',
                'unknown': '❓ *Unknown*',
                'error': '⚠️ *Error*'
            }.get(reachability, '')
            
            # Build vulnerability text
            vuln_text = f"*Package:* `{vuln['purl']}`\n\n{reach_indicator}\n"
            vuln_text += f"{finding['severity_emoji']} *{finding['cve_id']}*: {finding['severity'].upper()}"
            
            # Add trace if enabled and available
            if include_traces and reachability == 'reachable' and finding.get('trace'):
                # Format trace lines with indentation
                trace_lines = finding['trace'].split('\n')
                trace_text = '\n'.join(f"  {line}" for line in trace_lines if line.strip())
                if trace_text:
                    vuln_text += f"\n```\n{trace_text}\n```"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": vuln_text
                }
            })
            blocks.append({"type": "divider"})
        
        # Footer with omission notice and link (1-2 blocks)
        omitted_count = notification.get('omitted_count', 0)
        if omitted_count > 0:
            omitted_unreachable = notification.get('omitted_unreachable', 0)
            omitted_low = notification.get('omitted_low', 0)
            
            footer_parts = []
            if omitted_unreachable > 0:
                footer_parts.append(f"{omitted_unreachable} unreachable")
            if omitted_low > 0:
                footer_parts.append(f"{omitted_low} low severity")
            
            omission_text = f"⚠️ *{omitted_count} findings not shown*"
            if footer_parts:
                omission_text += f" ({', '.join(footer_parts)})"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": omission_text
                }
            })
        
        # Add link to full report if available
        if diff_url:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{diff_url}|View full report >"
                }
            })
        
        return blocks

    def _normalize_url_config(self, url_input):
        """
        Normalize URL configuration to a consistent list of dicts format.
        
        Args:
            url_input: Can be:
                - string: "https://webhook.url"
                - list of strings: ["https://webhook1.url", "https://webhook2.url"]
                - list of dicts: [{"url": "https://webhook.url", "name": "unique_name"}]
        
        Returns:
            List of dicts with 'url' and 'name' keys
        """
        if isinstance(url_input, str):
            return [{"url": url_input, "name": "default"}]
        
        if isinstance(url_input, list):
            normalized = []
            for idx, item in enumerate(url_input):
                if isinstance(item, str):
                    normalized.append({"url": item, "name": f"webhook_{idx}"})
                elif isinstance(item, dict):
                    if "url" not in item:
                        logger.warning(f"URL config item missing 'url' key: {item}")
                        continue
                    name = item.get("name", f"webhook_{idx}")
                    normalized.append({"url": item["url"], "name": name})
                else:
                    logger.warning(f"Invalid URL config item type: {type(item)}")
            return normalized
        
        logger.warning(f"Invalid URL config type: {type(url_input)}")
        return []

    @staticmethod
    def create_slack_blocks_from_diff(diff: Diff, config: CliConfig):
        pr = getattr(config, "pr_number", None)
        sha = getattr(config, "commit_sha", None)
        scan_link = getattr(diff, "diff_url", "")
        scan = f"<{scan_link}|scan>"
        title_part = ""
        if pr:
            title_part += f" for PR {pr}"
        if sha:
            title_part += f" - {sha[:8]}"
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Socket Security issues were found in this *{scan}*{title_part}*"
                }
            },
            {"type": "divider"}
        ]

        for alert in diff.new_alerts:
            manifest_str, source_str = Messages.create_sources(alert, "plain")
            manifest_str = manifest_str.lstrip("• ")
            source_str = source_str.lstrip("• ")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{alert.title}*\n"
                        f"<{alert.url}|{alert.purl}>\n"
                        f"*Introduced by:* `{source_str}`\n"
                        f"*Manifest:* `{manifest_str}`\n"
                        f"*CI Status:* {'Block' if alert.error else 'Warn'}"
                    )
                }
            })
            blocks.append({"type": "divider"})

        return blocks
