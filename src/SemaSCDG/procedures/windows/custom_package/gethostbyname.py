import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class gethostbyname(angr.SimProcedure):
    def run(self, hostname):
        try:
            print(self.state.mem[hostname].string.concrete)
        except:
            print(self.state.memory.load(hostname,0x20))
        addr = self.state.heap._malloc(8)
        self.state.memory.store(addr, self.state.solver.BVV("1.2.3.4"))
        return addr
