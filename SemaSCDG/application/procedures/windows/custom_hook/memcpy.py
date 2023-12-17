import angr
import logging

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class memcpy(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        # self.state.memory.store(dst_addr, self.state.memory.load(src_addr, 0x20))
        # return dst_addr
        if not self.state.solver.symbolic(limit):
            # not symbolic so we just take the value
            conditional_size = self.state.solver.eval(limit)
        else:
            # constraints on the limit are added during the store
            max_memcpy_size = self.state.libc.max_memcpy_size
            max_limit = self.state.solver.max_int(limit)
            min_limit = self.state.solver.min_int(limit)
            conditional_size = min(max_memcpy_size, max(min_limit, max_limit))
            if max_limit > max_memcpy_size and conditional_size < max_limit:
                lw.warning("memcpy upper bound of %#x outside limit, limiting to %#x instead",
                          max_limit, conditional_size)

        lw.debug("Memcpy running with conditional_size %#x", conditional_size)
        
        return dst_addr

