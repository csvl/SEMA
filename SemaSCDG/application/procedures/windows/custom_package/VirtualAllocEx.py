import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

def convert_prot(prot):
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


class VirtualAllocEx(angr.SimProcedure):
    def run(self,hProcess, lpAddress, dwSize, flAllocationType, flProtect):
        addr = self.state.solver.eval(lpAddress)
        addr &= ~0xfff
        size = self.state.solver.eval(dwSize)
        flags = self.state.solver.eval(flAllocationType)
        prot = self.state.solver.eval(flProtect)
        angr_prot = convert_prot(prot)

        if flags & 0x00002000 or addr == 0: # MEM_RESERVE
            if addr == 0:
                lw.debug("...searching for address")
                while True:
                    addr = self.allocate_memory(size)
                    try:
                        self.state.memory.map_region(addr, size, angr_prot, init_zero=True)
                    except angr.errors.SimMemoryError:
                        continue
                    else:
                        lw.debug("...found %#x", addr)
                        break
            else:
                try:
                    self.state.memory.map_region(addr, size, angr_prot, init_zero=True)
                except angr.errors.SimMemoryError:
                    lw.debug("...failed, bad address")
                    ret_expr = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
                    self.state.add_constraints(ret_expr != 0)
                    return ret_expr

        # if we got all the way to the end, nothing failed! success!
        return addr

    def allocate_memory(self,size):
        addr = self.state.heap.mmap_base
        new_base = addr + size

        if new_base & 0xfff:
            new_base = (new_base & ~0xfff) + 0x1000

        self.state.heap.mmap_base = new_base
        return addr
