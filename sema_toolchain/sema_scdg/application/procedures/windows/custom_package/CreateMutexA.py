import os
import sys


import logging
import angr

import os

import claripy

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
        self.state.solver.add(claripy.Or(retval == 0, retval == 1 ))
        return retval
