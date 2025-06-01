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


class strlen(angr.SimProcedure):
    #same code as the linux version
    def run(self, s):
        if s.symbolic:
            lw.debug("s is symbolic")
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)

        try:
            string = self.state.mem[s].string.concrete
            lw.debug("s is concrete")
            lw.debug(string)
            return len(string)
        except:
            lw.debug("s not resolvable")
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(s + i, 1)) == 0x0:
                    lw.debug("found length")
                    lw.debug(i)
                    return i
            lw.debug("can't find length")
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
