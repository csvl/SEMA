import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class RtlGetNtVersionNumbers(angr.SimProcedure):
    def run(self, MajorVersion, MinorVersion, BuildNumber):
        dwMajorVersion = self.state.solver.BVS("dwMajorVersion_{}".format(self.display_name),32)
        self.state.solver.add(dwMajorVersion > 4)
        self.state.solver.add(dwMajorVersion <= 10)
        self.state.memory.store(MajorVersion, dwMajorVersion,endness=self.arch.memory_endness)
        dwMinorVersion = self.state.solver.BVS("dwMinorVersion_{}".format(self.display_name),32)
        self.state.solver.add(dwMinorVersion >= 0)
        self.state.solver.add(dwMinorVersion < 4)
        self.state.memory.store(MinorVersion, dwMinorVersion,endness=self.arch.memory_endness)
        dwBuildNumber = self.state.solver.BVS("dwBuildNumber_{}".format(self.display_name),32)
        self.state.memory.store(BuildNumber, dwBuildNumber, endness=self.arch.memory_endness)
        return 0x0
