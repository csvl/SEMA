import angr
import logging
import claripy

l = logging.getLogger("CustomSimProcedureWindows")

class memmove(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_ptr, src_ptr, size):
        # Convert pointer addresses to memory addresses
        dst_addr = self.state.solver.eval(dst_ptr)
        src_addr = self.state.solver.eval(src_ptr)
        
        true_size = self.state.solver.eval(size)
        
        l.info("memmove(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        
        # Read source memory
        src_mem = self.state.memory.load(src_addr, size)

        l.info("memmove(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        # Create a symbolic bitvector for the destination memory
        #dst_mem = claripy.BVS("mem", size * 8)

        # Check for overlapping memory regions
        #overlap = dst_addr <= src_addr < dst_addr + true_size or src_addr <= dst_addr < src_addr + true_size
        l.info("memmove(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        
        # if overlap:
        #     l.info("memmoveA(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        #     # If the memory regions overlap, split the destination memory into two parts:
        #     # the part that does not overlap with the source memory and the part that does.
        #     offset = src_addr - dst_addr
        #     dst_mem1 = src_mem[:offset]
        #     dst_mem2 = src_mem[offset+true_size:]

        #     # Copy the non-overlapping part of the destination memory
        #     self.state.memory.store(dst_addr, dst_mem1)

        #     # Copy the overlapping part of the destination memory from the source memory
        #     self.state.memory.store(src_addr, src_mem[offset:offset+true_size])

        #     # Copy the remaining part of the destination memory
        #     self.state.memory.store(dst_addr+size, dst_mem2)

        #     # Return the final destination address
        #     return dst_ptr

        # else:
        l.info("memmoveB(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        # If the memory regions do not overlap, copy the source memory to the destination memory
        self.state.memory.store(dst_addr, src_mem)
        self.state.memory.erase(src_addr, size=true_size)

        # Return the final destination address
        return dst_ptr
