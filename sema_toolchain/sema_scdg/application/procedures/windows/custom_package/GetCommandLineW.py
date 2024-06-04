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

class GetCommandLineW(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        #return self.project.simos.wcmdln_ptr
