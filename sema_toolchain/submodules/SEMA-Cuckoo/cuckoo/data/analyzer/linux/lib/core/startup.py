import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.common.constants import PATHS
from lib.common.results import NetlogHandler

log = logging.getLogger()

def create_folders():
    """Create folders in PATHS."""
    for name, folder in list(PATHS.items()):
        if os.path.exists(folder):
            continue

        try:
            os.makedirs(folder)
        except OSError:
            pass

def init_logging():
    """Initialize logger."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)

    nh = NetlogHandler()
    nh.setFormatter(formatter)
    log.addHandler(nh)

    log.setLevel(logging.DEBUG)
