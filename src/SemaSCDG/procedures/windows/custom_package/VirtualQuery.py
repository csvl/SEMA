import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class VirtualQuery(angr.SimProcedure):
    def run(self, lpAddress, lpBuffer, dwLength):
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ret_val != 0)
        return ret_val
        # state = self.state
        # mem = state.memory

        # typedef struct _MEMORY_BASIC_INFORMATION {
        # PVOID  BaseAddress;
        # PVOID  AllocationBase;
        # DWORD  AllocationProtect;
        # WORD   PartitionId;
        # SIZE_T RegionSize;
        # DWORD  State;
        # DWORD  Protect;
        # DWORD  Type;
        # } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
                
        # Read the size of the structure from memory
        #size = mem.load(SimTypeInt().with_arch(state.arch), size_ptr)[0] # not used since we know the size of the structure
        # pvoid = 4 if self.state.arch.bits == 32 else 8
                
        # # Get the addresses of the structure fields
        # BaseAddress_ptr = lpBuffer + pvoid # TODO use ulong
        # AllocationBase_ptr = BaseAddress_ptr + pvoid
        # AllocationProtect = AllocationBase_ptr + 4
        # PartitionId = AllocationProtect + 2
        # RegionSize = PartitionId + pvoid
        # State = RegionSize + 4
        # Protect = State + 4
        # Type = Protect + 4

        # # Write the values of the structure fields to memory
        # mem.store(dwLength, 3*pvoid + 4*4 + 2*2, size=pvoid)
        # mem.store(AllocationBase_ptr, 7, size=pvoid)
        # mem.store(AllocationProtect, 0, size=4)
        # mem.store(PartitionId, 19041, size=2)
        # mem.store(RegionSize,  2, size=pvoid) # VER_PLATFORM_WIN32_NT
        # mem.store(State, size=4)
        # mem.store(Protect, size=4)
        # mem.store(Type, size=4)
        
        # ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        # self.state.solver.add(ret_val != 0)
        # return ret_val
