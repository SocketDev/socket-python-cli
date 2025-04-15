from . import jira, webhook, slack, teams

PLUGIN_CLASSES = {
    "jira": jira.JiraPlugin,
    "slack": slack.SlackPlugin,
    "webhook": webhook.WebhookPlugin,
    "teams": teams.TeamsPlugin,
}

class PluginManager:
    def __init__(self, config):
        self.plugins = []
        for name, conf in config.items():
            if conf.get("enabled"):
                plugin_cls = PLUGIN_CLASSES.get(name)
                if plugin_cls:
                    self.plugins.append(plugin_cls(conf))

    def send(self, diff, config):
        for plugin in self.plugins:
            plugin.send(diff, config)