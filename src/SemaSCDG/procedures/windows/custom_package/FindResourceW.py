import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class FindResourceW(angr.SimProcedure):
    def run(self, hModule, lpName, lpType):
        minaddr = self.state.project.loader.min_addr
        name = self.state.mem[lpName].wstring.concrete
        lw.info(name)
        rsrc = self.state.globals["rsrc"]
        offset = 0x10
        rsrctype =  self.state.solver.eval(self.state.memory.load(rsrc+offset,1))
        while rsrctype != self.state.solver.eval(lpType):
            offset += 8
            rsrctype =  self.state.solver.eval(self.state.memory.load(rsrc+offset,1))
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        offset += 0x10
        tablefind = self.state.solver.eval(self.state.memory.load(rsrc+offset,2,endness=archinfo.Endness.LE))
        size = self.state.solver.eval(self.state.memory.load(rsrc+tablefind,2,endness=archinfo.Endness.LE))
        rsrcname = self.state.solver.eval(self.state.memory.load(rsrc+tablefind+2,2*size))
        rsrcname = rsrcname.to_bytes(2*size, 'big')
        rsrcname = rsrcname.decode('utf-16le')
        while name != rsrcname:
            lw.info(rsrcname)
            offset += 8
            tablefind = self.state.solver.eval(self.state.memory.load(rsrc+offset,2,endness=archinfo.Endness.LE))
            size = self.state.solver.eval(self.state.memory.load(rsrc+tablefind,2,endness=archinfo.Endness.LE))
            rsrcname = self.state.solver.eval(self.state.memory.load(rsrc+tablefind+2,2*size))
            rsrcname = rsrcname.to_bytes(2*size, 'big')
            rsrcname = rsrcname.decode('utf-16le')
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        offset += 0x10
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        finaloffset = self.state.solver.eval(self.state.memory.load(rsrc+offset,4,endness=archinfo.Endness.LE))
        size = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,4,endness=archinfo.Endness.LE))
        resource = self.state.solver.eval(self.state.memory.load(minaddr+finaloffset,size,endness=archinfo.Endness.LE))
        self.state.plugin_resources.resources[finaloffset+minaddr] = {"size": size, "name": name, "data": resource, "rsrcname": rsrcname}
        x = finaloffset+minaddr
        lw.info(hex(x))
        return finaloffset+minaddr
        
