import angr
import logging
lw = logging.getLogger("CustomSimProcedureWindows")

class GetVersionExA(angr.SimProcedure):
    def run(self, lpVersionInformation):
        dwMajorVersion = self.state.solver.BVS("dwMajorVersion_{}".format(self.display_name),self.arch.bits)
        self.state.solver.add(dwMajorVersion > 4)
        self.state.solver.add(dwMajorVersion <= 10)
        self.state.memory.store(lpVersionInformation+0x4, dwMajorVersion,endness=self.arch.memory_endness)
        dwMinorVersion = self.state.solver.BVS("dwMinorVersion_{}".format(self.display_name),self.arch.bits)
        self.state.solver.add(dwMinorVersion >= 0)
        self.state.solver.add(dwMinorVersion < 4)
        self.state.memory.store(lpVersionInformation+0x8, dwMinorVersion,endness=self.arch.memory_endness)
        dwBuildNumber = self.state.solver.BVS("dwBuildNumber_{}".format(self.display_name),self.arch.bits)
        self.state.memory.store(lpVersionInformation+0xc, dwBuildNumber, endness=self.arch.memory_endness)
        dwPlatformId = self.state.solver.BVV(2,32)
        self.state.memory.store(lpVersionInformation+0x10, dwPlatformId, endness=self.arch.memory_endness)
        return 0x1
