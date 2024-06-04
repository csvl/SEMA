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


class HeapSize(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem):
        #TODO fix (wrong key error with redlinestealer timeout 300)
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)

        # return self.state.globals["HeapSize"][self.state.solver.eval(lpMem)]
