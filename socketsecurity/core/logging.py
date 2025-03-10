import logging


def initialize_logging(
    level: int = logging.INFO,
    format: str = "%(asctime)s: %(message)s",
    socket_logger_name: str = "socketdev",
    cli_logger_name: str = "socketcli"
) -> tuple[logging.Logger, logging.Logger]:
    """Initialize logging for Socket Security

    Returns both the socket and CLI loggers for convenience, though they can also
    be accessed via logging.getLogger() elsewhere
    """
    # Configure root logger
    logging.basicConfig(level=level, format=format)

    # Configure Socket logger
    socket_logger = logging.getLogger(socket_logger_name)
    socket_logger.setLevel(level)
    socket_logger.addHandler(logging.NullHandler())

    # Configure CLI logger
    cli_logger = logging.getLogger(cli_logger_name)
    cli_logger.setLevel(level)

    # Explicitly set urllib3 logger to WARNING to prevent debug messages
    # when not in debug mode
    urllib3_logger = logging.getLogger("urllib3")
    urllib3_logger.setLevel(logging.WARNING)

    # Also set git logger to WARNING
    git_logger = logging.getLogger("git")
    git_logger.setLevel(logging.WARNING)

    return socket_logger, cli_logger

def set_debug_mode(enable: bool = False) -> None:
    """Toggle debug logging across all loggers"""
    level = logging.DEBUG if enable else logging.INFO
    logging.getLogger("socketdev").setLevel(level)
    logging.getLogger("socketcli").setLevel(level)

    # Also update urllib3 and git loggers when debug mode changes
    urllib3_level = logging.DEBUG if enable else logging.WARNING
    logging.getLogger("urllib3").setLevel(urllib3_level)
    logging.getLogger("git").setLevel(urllib3_level)