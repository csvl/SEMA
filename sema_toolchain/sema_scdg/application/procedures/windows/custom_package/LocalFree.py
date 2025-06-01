
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


class LocalFree(angr.SimProcedure):
    def run(self, hMem):
        lw.debug("LocalFree.run")
        try:
            self.state.heap.free(hMem)
            return 0
        except:
            return hMem
