import logging
import time as timer
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetThreadContext(angr.SimProcedure):
    def run(self,hThread,lpContext):
        context = self.state.solver.BVS("CONTEXT_{}".format(self.display_name), 8*0x2cc)
        self.state.memory.store(lpContext, context)
        reg = self.state.solver.BVV(0x0, self.arch.bits)
        self.state.memory.store(lpContext+4, reg)   
        self.state.memory.store(lpContext+8, reg)   
        self.state.memory.store(lpContext+12, reg)   
        self.state.memory.store(lpContext+16, reg)     
        return 0x1
