import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class HeapSetInformation(angr.SimProcedure):
    def run(self, HeapHandle, HeapInformationClass, HeapInformation, HeapInformationLength):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
