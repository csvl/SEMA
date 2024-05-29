import logging
import sys
import angr
import archinfo

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class LoadResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        return hResInfo
