import angr
import claripy


class FindFirstFileW(angr.SimProcedure):
    def run(self, lpFileName, lpFindFileData):
        #print(self.state.mem(lpFileName).string.resolved)
        # TODO check if string is valid and not symbolic
        try:
            name = self.state.mem[lpFileName].wstring.concrete
            print(name)
        except:
            pass
        self.state.memory.store(lpFindFileData, claripy.BVS("WIN32_FIND_DATA", 8 * 320))
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
