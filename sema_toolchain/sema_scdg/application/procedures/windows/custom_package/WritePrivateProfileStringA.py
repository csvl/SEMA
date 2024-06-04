import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import claripy
import logging

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

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
