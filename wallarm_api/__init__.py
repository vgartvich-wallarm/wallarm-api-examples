"""
wallarm_api - package to fetch Wallarm API
"""
from . import wlrm

__author__ = "416e64726579"
__license__ = "MIT License"
__version__ = "0.2"

# Set default logging handler to avoid "No handler found" warnings.
import logging

try:
    from logging import NullHandler
except ImportError:

    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
