class Plugin:
    def __init__(self, config):
        self.config = config

    def send(self, message, level):
        raise NotImplementedError("Plugin must implement send()")