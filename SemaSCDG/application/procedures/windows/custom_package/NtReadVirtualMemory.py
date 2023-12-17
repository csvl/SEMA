import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class NtReadVirtualMemory(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToRead,
        NumberOfBytesReaded
    ):
        size = self.state.solver.eval(NumberOfBytesToRead)
        self.state.memory.store(Buffer, self.state.memory.load(BaseAddress,size))
        return 0x0
