import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class SetFilePointerEx(angr.SimProcedure):
    def run(self, hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod):
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ret_val > 0)
        return ret_val
