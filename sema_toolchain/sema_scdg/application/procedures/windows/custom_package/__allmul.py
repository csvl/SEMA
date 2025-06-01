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


class __allmul(angr.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4):
        lw.debug("enter __allmul")
        try:
            a = self.state.solver.eval(arg1)
            b = self.state.solver.eval(arg2)
            c = self.state.solver.eval(arg3)
            d = self.state.solver.eval(arg4)
            retval = self.state.solver.BVV(a*b*c*d,64)
        except:
            retval = self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        return retval
