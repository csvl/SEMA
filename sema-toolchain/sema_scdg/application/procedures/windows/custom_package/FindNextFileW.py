import angr
import claripy


class FindNextFileW(angr.SimProcedure):
    def run(self, hFindFile, lpFindFileData):
        self.state.globals["FindNextFile"] = 1
        if self.state.globals["FindNextFile"] == 0:
            self.state.globals["FindFirstFile"] == 1
            self.state.memory.store(lpFindFileData, claripy.BVS("dwFileAttributes", 8 * 4))
            self.state.memory.store(lpFindFileData+0x4, claripy.BVS("ftCreationTime", 8 * 8))
            self.state.memory.store(lpFindFileData+0xc, claripy.BVS("ftLastAccessTime", 8 * 8))
            self.state.memory.store(lpFindFileData+0x14, claripy.BVS("ftLastWriteTime", 8 * 8))
            self.state.memory.store(lpFindFileData+0x1c, claripy.BVS("nFileSizeHigh", 8 * 4))
            self.state.memory.store(lpFindFileData+0x20, claripy.BVS("nFileSizeLow", 8 * 4))
            self.state.memory.store(lpFindFileData+0x24, claripy.BVS("dwReserved0", 8 * 4))
            self.state.memory.store(lpFindFileData+0x28, claripy.BVS("dwReserved1", 8 * 4))
            self.state.memory.store(lpFindFileData+0x2c, claripy.BVS("cFileName", 8 * 2 * 260))
            self.state.memory.store(lpFindFileData+0x2c, claripy.BVV("ghijkl.cmd".encode('utf-16le')))
            self.state.memory.store(lpFindFileData+0x36, claripy.BVV(0x0,8 * 2 * 250))
            self.state.memory.store(lpFindFileData+0x130, claripy.BVS("cAlternateFileName", 8 * 2 * 14))
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val != -1)
            return ret_val
        else:
            self.state.globals["GetLastError"] = 18
            return 0
