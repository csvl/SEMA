import angr
import logging
lw = logging.getLogger("CustomSimProcedureWindows")

class inet_addr(angr.SimProcedure):

    def run(self, cp):
        try:
            print(self.state.mem[cp].string.concrete)
        except:
            print(self.state.memory.load(cp,0x20))
        return 123456
