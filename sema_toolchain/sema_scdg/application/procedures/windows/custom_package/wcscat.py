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


class wcscat(angr.SimProcedure):
    def run(self, dest, src):
        lw.debug("wcscat.run")
        #simplified strcat
        if dest.symbolic or src.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        first_str = self.state.mem[dest].wstring.concrete
        second_str = self.state.mem[src].wstring.concrete
        lw.debug("first_str: " + first_str)
        lw.debug("second_str: " + second_str)

        new_str = first_str + second_str + "\0"

        for i, ch in enumerate(new_str):
            self.state.memory.store(
                dest + i * 2,
                self.state.solver.BVV(ord(ch), 16),
                endness=self.state.arch.memory_endness
            )
        return dest

