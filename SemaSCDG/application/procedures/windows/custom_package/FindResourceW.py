import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class FindResourceW(angr.SimProcedure):
            
    def run(self, hModule, lpName, lpType):
        #https://blog.kowalczyk.info/articles/pefileformat.html
        
        def find(state, rsrc, offset):
            Id =  state.solver.eval(state.memory.load(rsrc+offset,4,endness=archinfo.Endness.LE))
            if Id >= 0x80000000:
                offsetToName = Id - 0x80000000
                sizeOfName = state.solver.eval(state.memory.load(rsrc+offsetToName,2,endness=archinfo.Endness.LE))
                Name = state.solver.eval(state.memory.load(rsrc+offsetToName+2,sizeOfName*2,endness=archinfo.Endness.LE))
                Name = Name.to_bytes(2*sizeOfName, 'little')
                Name = Name.decode('utf-16le')
                return Name
            return Id
        
        #Name or Id
        Name = self.state.mem[lpName].wstring.concrete
        NameInt = False
        if Name == '':
            Name = self.state.solver.eval(lpName)
            NameInt = True
        Type = self.state.mem[lpType].wstring.concrete
        TypeInt = False
        if Name == '':
            Type = self.state.solver.eval(lpType)
            TypeInt = True
        
        #Type directory
        rsrc = self.state.globals["rsrc"]
        nbTypes = self.state.solver.eval(self.state.memory.load(rsrc+0xc,2,endness=archinfo.Endness.LE))
        offset = 0x10
        if TypeInt:
            offset += 8 * nbTypes
            nbTypes = self.state.solver.eval(self.state.memory.load(rsrc+0xe,2,endness=archinfo.Endness.LE))
            
        TypeType = find(self.state, rsrc, offset)
        print(TypeType)
        
        while nbTypes > 0 and Type != TypeType:
            offset += 0x8
            nbTypes -= 1
            TypeType = find(self.state, rsrc, offset)
            
        if Type != TypeType:
            return 0
        
        #Name directory
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        nbNames = self.state.solver.eval(self.state.memory.load(rsrc+offset+0xc,2,endness=archinfo.Endness.LE))
        offset += 0x10
        if NameInt:
            offset += 8 * nbNames
            nbNames = self.state.solver.eval(self.state.memory.load(rsrc+offset+0xe,2,endness=archinfo.Endness.LE))
            
        NameName = find(self.state, rsrc, offset)
        print(NameName)
        
        while nbNames > 0 and Name != NameName:
            offset += 0x8
            nbNames -= 1
            NameName = find(self.state, rsrc, offset)
            
        if Name != NameName:
            return 0
            
        #Language directory
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,2,endness=archinfo.Endness.LE))
        offset = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x14,2,endness=archinfo.Endness.LE))

        #Data Entry
        finaloffset = self.state.solver.eval(self.state.memory.load(rsrc+offset,4,endness=archinfo.Endness.LE))
        size = self.state.solver.eval(self.state.memory.load(rsrc+offset+0x4,4,endness=archinfo.Endness.LE))
        minaddr = self.state.project.loader.min_addr
        addr = finaloffset+minaddr
        resource = self.state.solver.eval(self.state.memory.load(addr,size,endness=archinfo.Endness.LE))
        self.state.globals["resources"][addr] = size
        print(hex(addr))
        return addr
        
