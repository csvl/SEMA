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
                
        if not self.state.solver.symbolic(size):
            # not symbolic so we just take the value
            l.info("not symb")
            true_size = self.state.solver.eval(size)
        else:
            l.info("symb")
            # constraints on the limit are added during the store
            max_memcpy_size = self.state.libc.max_memcpy_size
            max_limit = self.state.solver.max_int(size)
            min_limit = self.state.solver.min_int(size)
            true_size = min(max_memcpy_size, max(min_limit, max_limit))
            if max_limit > max_memcpy_size and true_size < max_limit:
                l.info("memmove upper bound of %#x outside limit, limiting to %#x instead",
                          max_limit, true_size)

        l.info("memmove running with conditional_size %#x", true_size)
        
        l.info("memmove(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        
       
        l.info("memmove(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        # Create a symbolic bitvector for the destination memory
        #dst_mem = claripy.BVS("mem", size * 8)

        # Check for overlapping memory regions
        overlap = dst_addr <= src_addr < dst_addr + true_size or src_addr <= dst_addr < src_addr + true_size
        l.info("memmove(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
        
        if true_size > 0:
            if overlap:
                l.info("memmoveA(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
                # If the memory regions overlap, split the destination memory into two parts:
                # the part that does not overlap with the source memory and the part that does.
                
                # Cette fonction permet de copier un bloc de mémoire spécifié par le paramètre source dans un nouvel emplacement désigné par 
                # le paramètre destination. On peut donc dire que cette fonction est proche de la fonction memcpy. Néanmoins, la différence 
                # réside dans le fait que la fonction memmove accepte que les deux zones de mémoire puissent se chevaucher.

                # En cas de chevauchement, la copie se passe comme si les octets de la zone source étaient d'abord copiés dans une zone temporaire, 
                # qui ne chevauche aucune des deux zones pointées par source et destination, et les octets sont ensuite copiés de la zone temporaire 
                # vers la zone de destination.
                
                # Read source memory
                
                src_mem = self.state.memory.load(src_addr, size, endness='Iend_BE')
                
                tmp_addr = self.state.heap._malloc(size)
                self.state.memory.store(tmp_addr, src_mem, endness='Iend_BE')
                
                tmp_mem = self.state.memory.load(tmp_addr, size, endness='Iend_BE')
                self.state.memory.store(dst_addr, tmp_mem, endness='Iend_BE')
                
                self.state.heap._free(tmp_addr)
                
                # src_mem = self.state.memory.load(src_addr, true_size)   
                # offset = src_addr - dst_addr
                # src_mem1 = self.state.memory.load(src_addr, offset)                                #src_mem[:offset] -> 0:offset -> true_size_left = true_size-offset
                # src_mem2 = self.state.memory.load(src_addr+offset+true_size, true_size-offset)     #src_mem[offset+true_size:]
                # overlap_mem = self.state.memory.load(src_addr+offset, true_size)                   #src_mem[offset:offset+true_size]


                # # Copy the non-overlapping part of the destination memory
                # self.state.memory.store(dst_addr, src_mem1)

                # # Copy the overlapping part of the destination memory from the source memory
                # self.state.memory.store(src_addr, overlap_mem)

                # # Copy the remaining part of the destination memory
                # self.state.memory.store(dst_addr+true_size, src_mem2)

                # Return the final destination address

            else:
                # Read source memory
                src_mem = self.state.memory.load(src_addr, size, endness='Iend_BE')

                l.info("memmoveB(%#x, %#x, %#x)", dst_addr, src_addr, true_size)
                # If the memory regions do not overlap, copy the source memory to the destination memory
                self.state.memory.store(dst_addr, src_mem, endness='Iend_BE')
            #self.state.memory.erase(src_addr, size=true_size)

        # Return the final destination address
        return dst_addr
