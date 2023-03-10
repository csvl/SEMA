import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class PathFileExistsA(angr.SimProcedure):
    def run(self, pszPath):
        try:
            print(self.state.mem[pszPath].string.concrete)
        except:
            print(self.state.memory.load(pszPath,0x20))
        return 0x1
