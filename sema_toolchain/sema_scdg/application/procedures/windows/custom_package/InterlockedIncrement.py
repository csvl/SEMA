import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class InterlockedIncrement(angr.SimProcedure):
    def run(self, ptr):
        return self.state.mem[ptr].long.concrete + 1
