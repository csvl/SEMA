import angr
import claripy


class VirtualFree(angr.SimProcedure):
    def run(self, lpAddress, dwSize, dwFreeType):
        return 0x1
