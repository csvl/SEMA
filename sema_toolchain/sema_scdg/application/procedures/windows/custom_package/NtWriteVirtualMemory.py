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


class NtWriteVirtualMemory(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten
    ):
        x = self.state.solver.eval(NumberOfBytesToWrite)
        self.state.memory.store(BaseAddress, self.state.memory.load(Buffer,x))
        return 0x0
