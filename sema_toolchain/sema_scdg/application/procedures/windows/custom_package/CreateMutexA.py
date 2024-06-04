import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class CreateMutexA(angr.SimProcedure):
    def run(self, lpMutexAttributes, bInitialOwner, lpName):
        error = self.state.solver.BVS("error", self.arch.bits)
        self.state.solver.add(error != 0xb7)
        self.state.globals["GetLastError"] = error
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        self.state.solver.add(retval > 0)
        return retval
