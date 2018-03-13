"""simp_le logging"""
import logging
import time


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def setup_logging(verbose):
    """Setup basic logging."""
    level = logging.DEBUG if verbose else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt='%(asctime)s:%(levelname)s:%(name)s:%(lineno)d: %(message)s',
    )
    formatter.converter = time.gmtime  # UTC instead of localtime
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
