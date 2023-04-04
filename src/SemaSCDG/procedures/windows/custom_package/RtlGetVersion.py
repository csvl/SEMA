import logging
import angr
from angr.sim_type import SimTypeInt, SimTypePointer, SimTypeArray, SimTypeChar

lw = logging.getLogger("CustomSimProcedureWindows")

class RtlGetVersion(angr.SimProcedure):
    def run(self, lpVersionInformation):
        if self.state.arch.bits == 32:
            ulong = 0x4
        elif self.state.arch.bits == 64:
            ulong = 0x8
        dwMajorVersion = self.state.solver.BVS("dwMajorVersion_{}".format(self.display_name),self.state.arch.bits)
        self.state.solver.add(dwMajorVersion > 4)
        self.state.solver.add(dwMajorVersion <= 10)
        self.state.memory.store(lpVersionInformation+ulong, dwMajorVersion, endness=self.arch.memory_endness)
        dwMinorVersion = self.state.solver.BVS("dwMinorVersion_{}".format(self.display_name),self.state.arch.bits)
        self.state.solver.add(dwMinorVersion >= 0)
        self.state.solver.add(dwMinorVersion < 4)
        self.state.memory.store(lpVersionInformation+(2*ulong), dwMinorVersion, endness=self.arch.memory_endness)
        dwBuildNumber = self.state.solver.BVS("dwBuildNumber_{}".format(self.display_name),self.state.arch.bits)
        self.state.memory.store(lpVersionInformation+(3*ulong), dwBuildNumber, endness=self.arch.memory_endness)
        dwPlatformId = self.state.solver.BVV(2,self.state.arch.bits) # VER_PLATFORM_WIN32_NT: 2 ->  Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003, Windows XP, or Windows 2000.
        self.state.memory.store(lpVersionInformation+(4*ulong), dwPlatformId, endness=self.arch.memory_endness)
        return 0x0

    
