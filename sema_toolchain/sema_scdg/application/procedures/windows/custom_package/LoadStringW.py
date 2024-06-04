import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import sys
import angr
import archinfo

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class LoadStringW(angr.SimProcedure):
    def run(self, hInstance, uID, lpBuffer, cchBufferMax):
        rsrc = self.state.globals["rsrc"]
        offset = 0x10
        rsrctype =  self.state.solver.eval(self.state.memory.load(rsrc+offset,1))
        while rsrctype != 0x6:
            offset += 8
            rsrctype =  self.state.solver.eval(self.state.memory.load(rsrc+offset,1))
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        table = self.state.solver.eval(uID)//0x10
        offset += 0x10
        tablefind = self.state.solver.eval(self.state.memory.load(rsrc+offset,2,endness=archinfo.Endness.LE))
        while table != tablefind:
            offset += 0x8
            tablefind = self.state.solver.eval(self.state.memory.load(rsrc+offset,2,endness=archinfo.Endness.LE))
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x14,2,endness=archinfo.Endness.LE))
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset,4,endness=archinfo.Endness.LE))
        stringsize = self.state.solver.eval(self.state.memory.load(0x400000+offset,1,endness=archinfo.Endness.LE))
        stringnumber = self.state.solver.eval(uID) & 0xf
        x = self.state.solver.eval(self.state.memory.load(0x400000+offset+2,2*stringsize))
        y = x.to_bytes(2*stringsize, 'big')
        y += bytes([0])
        y += bytes([0])
        string = y.decode('utf-16le')
        lw.debug(string)
        ptr = self.state.solver.BVV(string)
        self.state.memory.store(lpBuffer,ptr)
        return stringsize
