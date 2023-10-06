import angr
import claripy


class CopyFileA(angr.SimProcedure):
    def run(self, lpExistingFileName, lpNewFileName, bFailIfExists):
        try:
            print(self.state.mem[lpExistingFileName].string.concrete)
        except:
            print(self.state.memory.load(lpExistingFileName,0x20))
        try:
            print(self.state.mem[lpNewFileName].string.concrete)
        except:
            print(self.state.memory.load(lpNewFileName,0x20))
        return 0x1
