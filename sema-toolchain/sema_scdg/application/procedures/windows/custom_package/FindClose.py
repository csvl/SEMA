import angr
import claripy


class FindClose(angr.SimProcedure):
    def run(self, hFindFile):
        return 0x1
