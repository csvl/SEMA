import angr
import claripy


class FindNextFileA(angr.SimProcedure):
    def run(self, lpFileName, lpFindFileData):
        return 0x0
