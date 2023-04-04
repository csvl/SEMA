import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InterlockedExchange(angr.SimProcedure):
    def run(self, target, value):
        retval = self.state.mem[target].long.concrete
        self.state.memory.store(target, value, endness=self.arch.memory_endness)
        return retval
