import angr
import logging
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class inet_addr(angr.SimProcedure):

    def run(self, cp):
        try:
            print(self.state.mem[cp].string.concrete)
        except:
            print(self.state.memory.load(cp,0x20))
        return 123456
