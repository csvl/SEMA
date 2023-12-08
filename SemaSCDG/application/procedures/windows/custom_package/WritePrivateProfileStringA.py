import angr
import claripy
import logging

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))

class WritePrivateProfileStringA(angr.SimProcedure):
    def run(self, lpAppName, lpKeyName, lpString, lpFileName):
        try:
            lw.debug(self.state.mem[lpAppName].string.concrete)
        except:
            lw.debug(self.state.memory.load(lpAppName,0x20))
        try:
            lw.debug(self.state.mem[lpKeyName].string.concrete)
        except:
            lw.debug(self.state.memory.load(lpKeyName,0x20))
        try:
            lw.debug(self.state.mem[lpString].string.concrete)
        except:
            lw.debug(self.state.memory.load(lpString,0x20))
        try:
            lw.debug(self.state.mem[lpFileName].string.concrete)
        except:
            lw.debug(self.state.memory.load(lpFileName,0x20))
        return 0x1
