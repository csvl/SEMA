import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class GetCommandLineW(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        #return self.project.simos.wcmdln_ptr
