import angr
import logging

l = logging.getLogger("CustomSimProcedureWindows")

# class memcpy(angr.SimProcedure):
#     #pylint:disable=arguments-differ

#     def run(self, dest, src, count):
#         if count.symbolic:
#             self.state.memory.store(dest, self.state.memory.load(src, 0x20))
#             return dest
           
#         else:
#             self.state.memory.store(dest, self.state.memory.load(src, self.state.solver.eval(count)))
#             return dest


class memcpy(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        if not self.state.solver.symbolic(limit):
            # not symbolic so we just take the value
            l.info("not symb")
            conditional_size = self.state.solver.eval(limit)
        else:
            l.info("symb")
            # constraints on the limit are added during the store
            max_memcpy_size = self.state.libc.max_memcpy_size
            max_limit = self.state.solver.max_int(limit)
            min_limit = self.state.solver.min_int(limit)
            conditional_size = min(max_memcpy_size, max(min_limit, max_limit))
            if max_limit > max_memcpy_size and conditional_size < max_limit:
                l.info("memcpy upper bound of %#x outside limit, limiting to %#x instead",
                          max_limit, conditional_size)

        l.info("Memcpy running with conditional_size %#x", conditional_size)

        if conditional_size > 0:
            if conditional_size < 0x18000000: #True: # conditional_size < 0x18000000
                l.info("conditional_size < 0x18000000")
                src_mem = self.state.memory.load(src_addr, conditional_size, endness='Iend_BE')
                l.info(src_addr)
                if ABSTRACT_MEMORY in self.state.options:
                    self.state.memory.store(dst_addr, src_mem, size=limit, endness='Iend_BE')
                else:
                    l.info(dst_addr)
                    self.state.memory.store(dst_addr, src_mem, size=conditional_size, endness='Iend_BE') # size=limit
            else:
                l.info("conditional_size >= 0x18000000")
                tenth = int(conditional_size/100)
                conditional_size =  int(conditional_size/100)
                l.info("new conditional_size {}".format(conditional_size))
                offset = 0
                for i in range(100):
                    l.info("submemcpy {}".format(i))
                    # return 0x0 # failure
                    inter_dst_addr = dst_addr + offset
                    inter_src_addr = src_addr + offset
                    # max_memcpy_size = self.state.libc.max_memcpy_size
                    # l.info(max_memcpy_size)
                    # max_limit = self.state.solver.max_int(limit)
                    # min_limit = self.state.solver.min_int(limit)
                    #conditional_size = min(max_memcpy_size, max(min_limit, max_limit))
                    src_mem = self.state.memory.load(inter_src_addr, conditional_size, endness='Iend_BE')
                    l.info(inter_src_addr)
                    if ABSTRACT_MEMORY in self.state.options:
                        self.state.memory.store(inter_dst_addr, src_mem, size=conditional_size, endness='Iend_BE')
                    else:
                        l.info(inter_dst_addr)
                        self.state.memory.store(inter_dst_addr, src_mem, size=conditional_size, endness='Iend_BE')
                    offset += int(conditional_size/100)

        return dst_addr

from angr.sim_options import ABSTRACT_MEMORY
