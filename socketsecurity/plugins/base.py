# Notification delivery must never be able to wedge a CI job. Every plugin
# HTTP call passes this explicitly; requests defaults to blocking forever.
REQUEST_TIMEOUT_SECONDS = 30


class Plugin:
    def __init__(self, config):
        self.config = config

    def send(self, diff, config):
        raise NotImplementedError("Plugin must implement send()")
