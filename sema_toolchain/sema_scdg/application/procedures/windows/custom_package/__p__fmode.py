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


class __p__fmode(angr.SimProcedure):
    def run(self, ):
        lw.debug("enter __p__fmode")
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        return retval
