import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


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
