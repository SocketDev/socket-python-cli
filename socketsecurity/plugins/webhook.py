from .base import Plugin
import requests

class WebhookPlugin(Plugin):
    def send(self, message, level):
        if not self.config.get("enabled", False):
            return
        if level not in self.config.get("levels", ["block", "warn"]):
            return

        url = self.config["url"]
        headers = self.config.get("headers", {"Content-Type": "application/json"})
        requests.post(url, json=message, headers=headers)