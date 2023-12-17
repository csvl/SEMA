import logging
import angr
import archinfo
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class OpenProcessToken(angr.SimProcedure):
    def run(self, ProcessHandle, DesiredAccess, TokenHandle):
        ptr = self.state.solver.BVS("TokenHandle_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ptr != 0)
        self.state.memory.store(TokenHandle,ptr,endness=archinfo.Endness.LE)
        return 0x1
