import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


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
