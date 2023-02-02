import angr
import claripy


class WritePrivateProfileStringA(angr.SimProcedure):
    def run(self, lpAppName, lpKeyName, lpString, lpFileName):
        try:
            print(self.state.mem[lpAppName].string.concrete)
        except:
            print(self.state.memory.load(lpAppName,0x20))
        try:
            print(self.state.mem[lpKeyName].string.concrete)
        except:
            print(self.state.memory.load(lpKeyName,0x20))
        try:
            print(self.state.mem[lpString].string.concrete)
        except:
            print(self.state.memory.load(lpString,0x20))
        try:
            print(self.state.mem[lpFileName].string.concrete)
        except:
            print(self.state.memory.load(lpFileName,0x20))
        return 0x1
