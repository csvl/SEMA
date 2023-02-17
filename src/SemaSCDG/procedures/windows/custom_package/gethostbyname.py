import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class gethostbyname(angr.SimProcedure):
    def run(self, hostname):
        try:
            lw.info(self.state.mem[hostname].string.concrete)
        except:
            lw.info(self.state.memory.load(hostname,0x20))
        # addr = self.state.heap._malloc(10)
        # self.state.memory.store(addr, self.state.solver.BVV("127.0.0.1"))
        # return addr
        return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )