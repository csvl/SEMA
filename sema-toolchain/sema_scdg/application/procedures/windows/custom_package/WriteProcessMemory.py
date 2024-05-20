import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class WriteProcessMemory(angr.SimProcedure):

    def run(
        self,
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten
    ):
        x = self.state.solver.eval(nSize)
        self.state.memory.store(lpBaseAddress, self.state.memory.load(lpBuffer,x),size=x)
        return 0x1
