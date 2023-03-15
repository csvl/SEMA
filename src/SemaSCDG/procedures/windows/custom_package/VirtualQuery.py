import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class VirtualQuery(angr.SimProcedure):
    def run(self, lpAddress, lpBuffer, dwLength):
    
        return self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)
        pvoid = 4 if self.state.arch.bits == 32 else 8
                
        # Get the addresses of the structure fields
        BaseAddress_ptr = lpBuffer + pvoid # TODO use ulong
        AllocationBase_ptr = BaseAddress_ptr + pvoid
        AllocationProtect = AllocationBase_ptr + 4
        PartitionId = AllocationProtect + 2
        RegionSize = PartitionId + pvoid
        State = RegionSize + 4
        Protect = State + 4
        Type = Protect + 4
        
        self.state.mem[BaseAddress_ptr].size_t = self.state.solver.BVS("BaseAddress_ptr_{}".format(self.display_name),self.arch.bits)
        self.state.mem[AllocationBase_ptr].size_t = self.state.solver.BVS("AllocationBase_ptr_{}".format(self.display_name),self.arch.bits)
        self.state.mem[AllocationProtect].dword = self.state.solver.BVS("AllocationProtect_{}".format(self.display_name),32)
        self.state.mem[PartitionId].word = self.state.solver.BVS("PartitionId_{}".format(self.display_name),16)
        self.state.mem[RegionSize].size_t = self.state.solver.BVS("RegionSize_{}".format(self.display_name),self.arch.bits)
        self.state.mem[State].dword = self.state.solver.BVS("State_{}".format(self.display_name),32)
        self.state.mem[Protect].dword = self.state.solver.BVS("Protect_{}".format(self.display_name),32)
        self.state.mem[Type].dword = self.state.solver.BVS("Type_{}".format(self.display_name),32)

        return dwLength
