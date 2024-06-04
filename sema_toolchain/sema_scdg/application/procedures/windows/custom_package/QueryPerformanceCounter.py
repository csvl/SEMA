import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import time as timer
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class QueryPerformanceCounter(angr.SimProcedure):
    def run(self, ptr):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            val = int(timer.perf_counter() * 1000000) + 12345678
            self.state.mem[ptr].qword = val
        else:
            self.state.mem[ptr].qword = self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        return 1
