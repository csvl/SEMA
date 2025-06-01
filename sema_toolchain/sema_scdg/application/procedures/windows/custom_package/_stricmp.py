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


class _stricmp(angr.SimProcedure):
    def run(self, str1, str2):
        lw.debug("enter _stricmp")
        try:
            str1_conc = self.state.mem[str1].string.concrete.decode('ascii').lower()
            str2_conc = self.state.mem[str2].string.concrete.decode('ascii').lower()

            lw.debug("Concrete strings: str1=%s, str2=%s", str1_conc, str2_conc)
            return (str1_conc < str2_conc) - (str1_conc > str2_conc)
        except:
            retval = self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
            return retval
