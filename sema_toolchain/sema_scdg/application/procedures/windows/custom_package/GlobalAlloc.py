import os
import sys
import logging
import angr

import os

import claripy

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class GlobalAlloc(angr.SimProcedure):
    def run(self, uFlags, dwBytes):
        lw.debug("GlobalAlloc.run")
        size = self.state.solver.eval(dwBytes)
        lw.debug(size)
        if size >= 0x100000:
            lw.debug("GlobalAlloc size >= 1MB, troncate to 256")
            return self.state.heap._malloc(0x100)
        # retval = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        # self.state.solver.add(claripy.Or(retval == 0, retval == self.state.heap._malloc(size)))
        # return retval

        return self.state.heap._malloc(size)