import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
import archinfo
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class OpenProcess(angr.SimProcedure):
    def run(self, dwDesiredAccess, bInheritHandle, dwProcessId):
        retval = self.state.solver.BVS("retval{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(retval != 0)
        return retval
