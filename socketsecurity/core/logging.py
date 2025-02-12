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

    return socket_logger, cli_logger

def set_debug_mode(enable: bool = True) -> None:
    """Toggle debug logging across all loggers"""
    level = logging.DEBUG if enable else logging.INFO
    logging.getLogger("socketdev").setLevel(level)
    logging.getLogger("socketcli").setLevel(level)