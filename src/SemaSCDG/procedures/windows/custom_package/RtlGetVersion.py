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
#         dwMajorVersion = self.state.solver.BVS("dwMajorVersion_{}".format(self.display_name),self.state.arch.bits)
#         self.state.solver.add(dwMajorVersion > 4)
#         self.state.solver.add(dwMajorVersion <= 10)
#         self.state.memory.store(lpVersionInformation+ulong, dwMajorVersion, endness=self.arch.memory_endness)
#         dwMinorVersion = self.state.solver.BVS("dwMinorVersion_{}".format(self.display_name),self.state.arch.bits)
#         self.state.solver.add(dwMinorVersion >= 0)
#         self.state.solver.add(dwMinorVersion < 4)
#         self.state.memory.store(lpVersionInformation+(2*ulong), dwMinorVersion, endness=self.arch.memory_endness)
#         dwBuildNumber = self.state.solver.BVS("dwBuildNumber_{}".format(self.display_name),self.state.arch.bits)
#         self.state.memory.store(lpVersionInformation+(3*ulong), dwBuildNumber, endness=self.arch.memory_endness)
#         dwPlatformId = self.state.solver.BVV(2,self.state.arch.bits) # VER_PLATFORM_WIN32_NT: 2 ->  Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003, Windows XP, or Windows 2000.
#         self.state.memory.store(lpVersionInformation+(4*ulong), dwPlatformId, endness=self.arch.memory_endness)
#         return 0x0
        # Get the state and the memory model
        state = self.state
        mem = state.memory

        # Read the size of the structure from memory
        size_ptr = lpVersionInformation
        #size = mem.load(SimTypeInt().with_arch(state.arch), size_ptr)[0] # not used since we know the size of the structure

        # Get the addresses of the structure fields
        major_version_ptr = lpVersionInformation + ulong # TODO use ulong
        minor_version_ptr = lpVersionInformation + (2*ulong)
        build_number_ptr = lpVersionInformation + (3*ulong)
        platform_id_ptr = lpVersionInformation + (4*ulong)
        csd_version_ptr = lpVersionInformation + (5*ulong)

        # Write the values of the structure fields to memory
        mem.store(size_ptr, 5*ulong + len(b"Service Pack 3\0"), size=ulong)
        mem.store(major_version_ptr, 7, size=ulong)
        mem.store(minor_version_ptr, 0, size=ulong)
        mem.store(build_number_ptr, 19041, size=ulong)
        mem.store(platform_id_ptr,  2, size=ulong) # VER_PLATFORM_WIN32_NT
        mem.store(csd_version_ptr, b"Service Pack 3\0")
        return 0x0

    
