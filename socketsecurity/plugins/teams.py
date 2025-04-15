from .base import Plugin
import requests

class TeamsPlugin(Plugin):
    def send(self, message, level):
        if not self.config.get("enabled", False):
            return
        if level not in self.config.get("levels", ["block", "warn"]):
            return

        payload = {"text": message.get("title", "No title")}
        requests.post(self.config["webhook_url"], json=payload)