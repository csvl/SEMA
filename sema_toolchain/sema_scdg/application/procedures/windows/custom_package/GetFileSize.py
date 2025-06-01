import os
import sys


import logging
import angr

import os

import claripy

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class GetFileSize(angr.SimProcedure):
    def run(self, hFile, lpFileSizeHigh):
        if hFile.symbolic:
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val != 0xFFFFFFFF)
            return ret_val
        simfd = self.state.posix.get_fd(hFile)
        # import pdb; pdb.set_trace()
        if simfd is None:
            lw.debug("GetFileSize: could not find fd")
            return self.state.solver.BVS("retval_{}".format(self.display_name),  self.arch.bits)
        lw.debug(
            "GetFileSize: {}  asks file size of {}".format(self.display_name, hFile)
        )
        size = simfd.size()

        if not size.symbolic and self.state.solver.eval(size) != 0:
            return size
        else:
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.add_constraints(claripy.Or(ret_val == 0, ret_val == 1))
            return ret_val
