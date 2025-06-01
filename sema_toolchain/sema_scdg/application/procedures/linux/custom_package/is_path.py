import os
import sys
import logging
import angr
import claripy
from angr.procedures.libc.system import system

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class is_path(angr.SimProcedure):
    def run(self, path):
        lw.debug("is_path?")

        ret_val = self.state.solver.BVS('ret_val', self.state.arch.bits)
        self.state.solver.add(claripy.Or(ret_val == 1, ret_val == 0))

        return ret_val