import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class LoadStringA(angr.SimProcedure):
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
        string = y.decode('utf-16')
        ptr = self.state.solver.BVV(string)
        self.state.memory.store(lpBuffer,ptr)
        return stringsize
