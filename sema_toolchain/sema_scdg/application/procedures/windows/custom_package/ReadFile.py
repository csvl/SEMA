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


class ReadFile(angr.SimProcedure):
    def run(
        self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped
    ):

        self.state.project
        simfd = self.state.posix.get_fd(hFile)
        if simfd is None:
            lw.warning("ReadFile: could not find fd")
            return 1
        bytes_read = simfd.read(
            lpBuffer, nNumberOfBytesToRead, endness=self.arch.memory_endness
        )
        self.state.memory.store(
            lpNumberOfBytesRead, bytes_read, endness=self.arch.memory_endness
        )
        return 1
        # return self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)
