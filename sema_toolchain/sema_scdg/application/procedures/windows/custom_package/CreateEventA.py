import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class CreateEventA(angr.SimProcedure):

    def run(
        self,
        lpEventAttributes,
        bManualReset,
        bInitialState,
        lpName
    ):
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ret_val > 0x0)
        return ret_val
