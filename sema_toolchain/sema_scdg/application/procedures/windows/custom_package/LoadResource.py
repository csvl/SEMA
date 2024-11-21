import os
import sys


import logging
import sys
import angr
import archinfo

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class LoadResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        return hResInfo
