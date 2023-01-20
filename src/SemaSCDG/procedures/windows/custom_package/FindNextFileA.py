import angr
import claripy


class FindNextFileA(angr.SimProcedure):
    def run(self, lpFileName, lpFindFileData):
        self.state.memory.store(lpFindFileData, claripy.BVS("WIN32_FIND_DATA", 8 * 320))
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
