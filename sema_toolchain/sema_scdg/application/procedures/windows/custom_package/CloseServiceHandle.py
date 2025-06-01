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


class CloseServiceHandle(angr.SimProcedure):
    def run(self, arg1):
        lw.debug("Enter CloseServiceHandle")
        return 1
