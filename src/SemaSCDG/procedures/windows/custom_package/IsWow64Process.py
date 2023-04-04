import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class IsWow64Process(angr.SimProcedure):
    def run(
        self,
        hProcess,
        Wow64Process
    ):
        
        wow = self.state.solver.BVS(
                "Wow_64_process_{}".format(self.display_name),  self.arch.bits
            )
        wow = self.state.solver.BVV(0, self.arch.bits)
        self.state.memory.store(Wow64Process, wow)
        return 0x1
