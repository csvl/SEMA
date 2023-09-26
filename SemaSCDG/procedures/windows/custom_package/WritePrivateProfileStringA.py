import angr
import claripy
import logging

l = logging.getLogger("CustomSimProcedureWindows")

class WritePrivateProfileStringA(angr.SimProcedure):
    def run(self, lpAppName, lpKeyName, lpString, lpFileName):
        try:
            l.info(self.state.mem[lpAppName].string.concrete)
        except:
            l.info(self.state.memory.load(lpAppName,0x20))
        try:
            l.info(self.state.mem[lpKeyName].string.concrete)
        except:
            l.info(self.state.memory.load(lpKeyName,0x20))
        try:
            l.info(self.state.mem[lpString].string.concrete)
        except:
            l.info(self.state.memory.load(lpString,0x20))
        try:
            l.info(self.state.mem[lpFileName].string.concrete)
        except:
            l.info(self.state.memory.load(lpFileName,0x20))
        return 0x1
