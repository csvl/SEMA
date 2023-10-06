import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class gethostbyname(angr.SimProcedure):
    def run(self, hostname):
        try:
            lw.info(self.state.mem[hostname].string.concrete)
        except:
            lw.info(self.state.memory.load(hostname,0x20))
        return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
