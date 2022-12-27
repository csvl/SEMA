import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class OpenProcessToken(angr.SimProcedure):
    def run(self, ProcessHandle, DesiredAccess, TokenHandle):
        ptr = self.state.solver.BVS("TokenHandle_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ptr != 0)
        self.state.memory.store(TokenHandle,ptr)
        return 0x1
