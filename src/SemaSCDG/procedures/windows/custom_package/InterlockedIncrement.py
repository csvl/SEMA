import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InterlockedIncrement(angr.SimProcedure):
    def run(self, ptr):
        return self.state.mem[ptr].long.concrete + 1
