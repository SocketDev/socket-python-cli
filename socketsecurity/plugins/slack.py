import logging
import requests
from socketsecurity.config import CliConfig
from .base import Plugin
from socketsecurity.core.classes import Diff
from socketsecurity.core.messages import Messages

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
        else:
            url = self.config.get("url")

        if not diff.new_alerts:
            logger.debug("No new alerts to notify via Slack.")
            return

        logger.debug("Slack Plugin Enabled")
        logger.debug("Alert levels: %s", self.config.get("levels"))

        message = self.create_slack_blocks_from_diff(diff, config)
        logger.debug(f"Sending message to {url}")
        
        if config.enable_debug:
            logger.debug(f"Slack webhook URL: {url}")
            logger.debug(f"Number of alerts to send: {len(diff.new_alerts)}")
            logger.debug(f"Message blocks count: {len(message)}")
        
        response = requests.post(
            url,
            json={"blocks": message}
        )

        if response.status_code >= 400:
            logger.error("Slack error %s: %s", response.status_code, response.text)
        elif config.enable_debug:
            logger.debug(f"Slack webhook response: {response.status_code}")

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
