import logging
import angr
import struct

lw = logging.getLogger("CustomSimProcedureWindows")

class GetSystemInfo(angr.SimProcedure):
    def run(self, lpSystemInfo):
        if lpSystemInfo.symbolic:
            return
        wProcessorArchitecture = self.state.solver.BVS("wProcessorArchitecture_{}".format(self.display_name), 16)
        self.state.memory.store(lpSystemInfo, wProcessorArchitecture, endness=self.arch.memory_endness)
        wReserved = self.state.solver.BVS("wReserved_{}".format(self.display_name), 16)
        self.state.memory.store(lpSystemInfo + 2, wReserved, endness=self.arch.memory_endness)
        dwPageSize = self.state.solver.BVS("dwPageSize_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 4, dwPageSize, endness=self.arch.memory_endness)
        lpMinimumApplicationAddress = self.state.solver.BVS("lpMinimumApplicationAddress_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 8, lpMinimumApplicationAddress, endness=self.arch.memory_endness)
        lpMaximumApplicationAddress = self.state.solver.BVS("lpMaximumApplicationAddress_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 12, lpMaximumApplicationAddress, endness=self.arch.memory_endness)
        dwActiveProcessorMask = self.state.solver.BVS("dwActiveProcessorMask_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 16, dwActiveProcessorMask, endness=self.arch.memory_endness)
        dwNumberOfProcessors = self.state.solver.BVS("dwNumberOfProcessors_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 20, dwNumberOfProcessors, endness=self.arch.memory_endness)
        dwProcessorType = self.state.solver.BVS("dwProcessorType_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 24, dwProcessorType, endness=self.arch.memory_endness)
        dwAllocationGranularity = self.state.solver.BVS("dwAllocationGranularity_{}".format(self.display_name), 32)
        self.state.memory.store(lpSystemInfo + 28, dwAllocationGranularity, endness=self.arch.memory_endness)
        wProcessorLevel = self.state.solver.BVS("wProcessorLevel_{}".format(self.display_name), 16)
        self.state.memory.store(lpSystemInfo + 32, wProcessorLevel, endness=self.arch.memory_endness)
        wProcessorLevel = self.state.solver.BVS("wProcessorRevision_{}".format(self.display_name), 16)
        self.state.memory.store(lpSystemInfo + 34, wProcessorLevel, endness=self.arch.memory_endness)
        return
