import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class Time(angr.SimProcedure):
    def run(self, timer):
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        if timer:
            self.state.memory.store(timer, ret_val)

        return ret_val
