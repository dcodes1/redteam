import logging
import sys


def init_logger(verbosity: int = 0) -> logging.Logger:
    """
    Initialize root logger with verbosity levels:
    -v sets INFO, -vv sets DEBUG
    Defaults to WARNING.
    """
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(level)
    # Avoid duplicate handlers on multiple inits
    if not logger.handlers:
        logger.addHandler(handler)
    else:
        logger.handlers = [handler]

    return logger
