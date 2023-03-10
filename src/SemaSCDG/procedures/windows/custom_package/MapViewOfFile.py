import angr
import claripy
import logging

# 06 08 02 07 0d 0c 05 0a 0f 06 06 01 0f 0b 0b 04 0b 0f 06 04 0b 0c 06 02 05 0c 07 08 02 08 03 0e 0f 08 03 06 0c 06 09 08 05 0b 0b 02 0b 0f 0b 08 03 06 0b 0d 00 0c 08 0d 05 03 09 07 03 03 02 0. 0e 0x 0e 0 0 0

l = logging.getLogger("CustomSimProcedureWindows")

class MapViewOfFile(angr.SimProcedure):
    def run(self, hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap):
        # Get the handle to the file mapping object
        l.info(self.state.globals["files_fd"])
        if hFileMappingObject in  self.state.globals["files_fd"]:
            simfd =  self.state.posix.get_fd(self.state.globals["files_fd"][hFileMappingObject]) #self.state.posix.get_fd(hFile)
        else:
            simfd = None
        
        size = self.state.solver.eval(dwNumberOfBytesToMap) #simfd.size()
        l.info(size)
        
        addr = self.allocate_memory(size)
        
        access = self.state.solver.eval(dwDesiredAccess)
        access & (1 << 31) or (access & (1 << 16))
        access & (1 << 30)
        access & (1 << 29)
        access & (1 << 28)
        
        # prots = self.state.solver.eval_upto(dwDesiredAccess, 2)
        # if len(prots) != 1:
        #     raise angr.errors.SimValueError("MapViewOfFile can't handle symbolic flProtect")
        # prot = prots[0]
        # angr_prot = convert_prot(prot)
        
        # Get the file offset
        file_offset = (self.state.solver.eval(dwFileOffsetHigh) << 32) + self.state.solver.eval(dwFileOffsetLow)
            
        self.state.memory.map_region(addr, size, access, init_zero=True)
        
        saved_pos = simfd.tell()
        simfd.seek(self.state.solver.eval(file_offset), whence="start")
        data, _ = simfd.read_data(size)
        simfd.seek(saved_pos, whence="start")
        l.info(data)
        self.state.memory.store(addr, data)
        
        return addr
        

    def allocate_memory(self,size):
        addr = self.state.heap.mmap_base
        new_base = addr + size

        if new_base & 0xfff:
            new_base = (new_base & ~0xfff) + 0x1000

        self.state.heap.mmap_base = new_base

        return addr
    
def convert_prot(prot):
    """
    Convert from a windows memory protection constant to an angr bitmask
    """
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
    if prot & 0x10:
        return 4
    if prot & 0x20:
        return 5
    if prot & 0x40:
        return 7
    if prot & 0x80:
        return 7
    if prot & 0x01:
        return 0
    if prot & 0x02:
        return 1
    if prot & 0x04:
        return 3
    if prot & 0x08:
        return 3
    raise angr.errors.SimValueError("Unknown windows memory protection constant: %#x" % prot)

def deconvert_prot(prot):
    """
    Convert from a angr bitmask to a windows memory protection constant
    """
    if prot in (2, 6):
        raise angr.errors.SimValueError("Invalid memory protection for windows process")
    return [0x01, 0x02, None, 0x04, 0x10, 0x20, None, 0x40][prot]

