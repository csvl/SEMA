import angr
import logging
lw = logging.getLogger("CustomSimProcedureWindows")

class GetVersionExA(angr.SimProcedure):
    def run(self, lpVersionInformation):
        self.state.memory.store(lpVersionInformation+0x10, self.state.solver.BVV(2, self.arch.bits),endness=self.arch.memory_endness)
        dwMajorVersion = self.state.solver.BVS("dwMajorVersion", self.arch.bits)
        self.state.solver.add(dwMajorVersion > 4)
        self.state.memory.store(lpVersionInformation+0x4, dwMajorVersion,endness=self.arch.memory_endness)
        dwMinorVersion = self.state.solver.BVS("dwMinorVersion", self.arch.bits)
        self.state.solver.add(dwMinorVersion >= 0)
        self.state.solver.add(dwMinorVersion < 4)
        self.state.memory.store(lpVersionInformation+0x8, dwMinorVersion,endness=self.arch.memory_endness)
        return 1
