import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


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
