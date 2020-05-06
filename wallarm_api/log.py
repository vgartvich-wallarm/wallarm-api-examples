"""Logging configuration."""

import logging
import os

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()

logging.basicConfig(level=LOGLEVEL, format='%(asctime)s %(name)s %(levelname)s:%(message)s')
logger = logging.getLogger(__package__)
