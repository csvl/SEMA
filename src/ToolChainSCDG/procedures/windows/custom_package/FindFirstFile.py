import angr
import claripy


class FindFirstFile(angr.SimProcedure):
    def run(self, lpFileName, lpFindFileData):
        self.state.memory.store(lpFindFileData, claripy.BVS("WIN32_FIND_DATA", 8 * 320))
        ret_expr = claripy.BVS("handle_first_file", 32)
        return ret_expr
