import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetFileAttributesA(angr.SimProcedure):
    def run(self, lpFileName):
        try:
            print(self.state.mem[lpFileName].string.concrete)
        except:
            print(self.state.memory.load(lpFileName,0x20))
        return -1  #fail pour gh0strat
