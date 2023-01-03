import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


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
