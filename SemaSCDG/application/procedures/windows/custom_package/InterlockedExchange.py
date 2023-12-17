import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class InterlockedExchange(angr.SimProcedure):
    def run(self, target, value):
        retval = self.state.mem[target].long.concrete
        self.state.memory.store(target, value, endness=self.arch.memory_endness)
        return retval
