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


class __setusermatherr(angr.SimProcedure):
    def run(self, handler_ptr):
        lw.debug("custom math err set")
        try:
            lw.debug("white error : %s",self.state.mem[handler_ptr].string.concrete)
        except:
            lw.debug("non concrete message")

        return 0
