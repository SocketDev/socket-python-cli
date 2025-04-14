from .base import Plugin
import requests
import base64

class JiraPlugin(Plugin):
    def send(self, message, level):
        if not self.config.get("enabled", False):
            return
        if level not in self.config.get("levels", ["block", "warn"]):
            return

        url = self.config["url"]
        project = self.config["project"]
        auth = base64.b64encode(f"{self.config['email']}:{self.config['api_token']}".encode()).decode()

        payload = {
            "fields": {
                "project": {"key": project},
                "summary": message.get("title", "No title"),
                "description": message.get("description", ""),
                "issuetype": {"name": "Task"}
            }
        }

        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }

        requests.post(f"{url}/rest/api/3/issue", json=payload, headers=headers)