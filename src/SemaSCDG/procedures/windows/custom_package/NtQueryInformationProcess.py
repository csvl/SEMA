import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class NtQueryInformationProcess(angr.SimProcedure):
    def run(
        self,
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength
    ):
        if ProcessInformationClass.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        class_type = self.state.solver.eval(ProcessInformationClass)
        
        if class_type == 0: #ProcessBasicInformation
            procinfo = self.state.solver.BVS("Process_basic_info_{}".format(self.display_name), 64)
            self.state.memory.store(ProcessInformation, procinfo)
            teb_addr = self.state.regs.fs.concat(self.state.solver.BVV(0, 16))
            self.state.memory.store(ProcessInformation + 4, self.state.memory.load(teb_addr + 0x30,4))
            
        if class_type == 7: #ProcessDebugPort
            procinfo = self.state.solver.BVV(0x0, self.arch.bits)
            self.state.memory.store(ProcessInformation, procinfo)
        
        if class_type == 0x1E: #ProcessDebugObjectHandle
            procinfo = self.state.solver.BVV(0x0, self.arch.bits)
            self.state.memory.store(ProcessInformation, procinfo)
            
        if class_type == 0x1F: #ProcessDebugFlags
            procinfo = self.state.solver.BVV(0x1, self.arch.bits)
            self.state.memory.store(ProcessInformation, procinfo)
        
        return 0x0
