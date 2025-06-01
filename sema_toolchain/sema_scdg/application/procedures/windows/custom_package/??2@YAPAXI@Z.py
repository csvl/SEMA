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

# ??2@YAPAXI@Z
class NewInt(angr.SimProcedure):
    ALT_NAMES = "??2@YAPAXI@Z"
    def run(
        self,
        uint,
    ):
        lw.debug("New Int")
        size = self.state.solver.eval(uint)
        lw.debug(size)
        return self.state.heap._malloc(size)
