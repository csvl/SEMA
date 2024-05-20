import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class InterlockedIncrement(angr.SimProcedure):
    def run(self, ptr):
        return self.state.mem[ptr].long.concrete + 1
