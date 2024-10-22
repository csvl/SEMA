import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from . import sig1, sig2, sig3
from .sigsub import sigsub1, sigsub2

class meta:
    plugins = sig1.Sig1, sig2.Sig2, sig3.Sig3, sigsub1.Sigsub1, sigsub2.Sigsub2
