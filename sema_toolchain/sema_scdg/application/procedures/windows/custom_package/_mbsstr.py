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


class _mbsstr(angr.SimProcedure):
    def run(self, str_ptr, substr_ptr):
        lw.debug("enter mbsstr")
        try:
            str_conc = self.state.mem[str_ptr].string.concrete
            substr_conc = self.state.mem[substr_ptr].string.concrete
            lw.debug("Concrete strings: str=%s, substr=%s", str_conc, substr_conc)
            offset = str_conc.find(substr_conc)
            return str_ptr + offset
        except:
            retval = self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
            return retval
