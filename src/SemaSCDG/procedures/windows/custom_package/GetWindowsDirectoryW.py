import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetWindowsDirectoryW(angr.SimProcedure):
    def run(self, lpBuffer, uSize):
        size = self.state.solver.eval(uSize)
        path = self.state.solver.BVV(b'C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\x00\x00')
        self.state.memory.store(lpBuffer, path)
        return 20
