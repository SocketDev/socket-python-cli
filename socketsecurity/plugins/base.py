class Plugin:
    def __init__(self, config):
        self.config = config

    def send(self, diff, config):
        raise NotImplementedError("Plugin must implement send()")