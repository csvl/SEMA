import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class wcsrchr(angr.SimProcedure):
    def run(self, s, ch):
        lw.debug("wsrchr.run")
        if s.symbolic or ch.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        first_str = self.state.mem[s].wstring.concrete
        ch_val = chr(self.state.solver.eval(ch))
        lw.debug(f"Searching for: {repr(ch_val)} in {repr(first_str)}")

        index = first_str.rfind(ch_val)
        if index == -1:
            return 0
        return s + index*2