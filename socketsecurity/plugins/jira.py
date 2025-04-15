from .base import Plugin
import requests
import base64
from socketsecurity.core.classes import Diff
from socketsecurity.config import CliConfig
from socketsecurity.core import log


class JiraPlugin(Plugin):
    def send(self, diff: Diff, config: CliConfig):
        if not self.config.get("enabled", False):
            return
        log.debug("Jira Plugin Enabled")
        alert_levels = self.config.get("levels", ["block", "warn"])
        log.debug(f"Alert levels: {alert_levels}")
        # has_blocking = any(getattr(a, "blocking", False) for a in diff.new_alerts)
        # if "block" not in alert_levels and has_blocking:
        #     return
        # if "warn" not in alert_levels and not has_blocking:
        #     return
        parts = ["Security Issues found in Socket Security results"]
        pr = getattr(config, "pr_number", "")
        sha = getattr(config, "commit_sha", "")[:8] if getattr(config, "commit_sha", "") else ""
        scan_link = getattr(diff, "diff_url", "")

        if pr and pr != "0":
            parts.append(f"for PR {pr}")
        if sha:
            parts.append(f"- {sha}")
        title = " ".join(parts)

        description_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Security issues were found in this scan:"},
                        {"type": "text", "text": "\n"},
                        {
                            "type": "text",
                            "text": "View Socket Security scan results",
                            "marks": [{"type": "link", "attrs": {"href": scan_link}}]
                        }
                    ]
                },
                self.create_adf_table_from_diff(diff)
            ]
        }
        # log.debug("ADF Description Payload:\n" + json.dumps(description_adf, indent=2))
        log.debug("Sending Jira Issue")
        # 🛠️ Build and send the Jira issue
        url = self.config["url"]
        project = self.config["project"]
        auth = base64.b64encode(
            f"{self.config['email']}:{self.config['api_token']}".encode()
        ).decode()

        payload = {
            "fields": {
                "project": {"key": project},
                "summary": title,
                "description": description_adf,
                "issuetype": {"name": "Task"}
            }
        }

        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        jira_url = f"{url}/rest/api/3/issue"
        log.debug(f"Jira URL: {jira_url}")
        response = requests.post(jira_url, json=payload, headers=headers)
        if response.status_code >= 300:
            log.error(f"Jira error {response.status_code}: {response.text}")
        else:
            log.info(f"Jira ticket created: {response.json().get('key')}")

    @staticmethod
    def flatten_adf_to_text(adf):
        def extract_text(node):
            if isinstance(node, dict):
                if node.get("type") == "text":
                    return node.get("text", "")
                return "".join(extract_text(child) for child in node.get("content", []))
            elif isinstance(node, list):
                return "".join(extract_text(child) for child in node)
            return ""

        return extract_text(adf)

    @staticmethod
    def create_adf_table_from_diff(diff):
        from socketsecurity.core.messages import Messages

        def make_cell(text):
            return {
                "type": "tableCell",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": text}]
                    }
                ]
            }

        def make_link_cell(text, url):
            return {
                "type": "tableCell",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": text,
                            "marks": [{"type": "link", "attrs": {"href": url}}]
                        }]
                    }
                ]
            }

        # Header row (must use tableCell not tableHeader!)
        header_row = {
            "type": "tableRow",
            "content": [
                make_cell("Alert"),
                make_cell("Package"),
                make_cell("Introduced by"),
                make_cell("Manifest File"),
                make_cell("CI")
            ]
        }

        rows = [header_row]

        for alert in diff.new_alerts:
            manifest_str, source_str = Messages.create_sources(alert, "plain")

            row = {
                "type": "tableRow",
                "content": [
                    make_cell(alert.title),
                    make_link_cell(alert.purl, alert.url) if alert.url else make_cell(alert.purl),
                    make_cell(source_str),
                    make_cell(manifest_str),
                    make_cell("🚫" if alert.error else "⚠️")
                ]
            }

            rows.append(row)

        # Final return is a block array
        return {
            "type": "table",
            "content": rows
        }
