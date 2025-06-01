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


class _CxxThrowException(angr.SimProcedure):
    def run(self, pExceptionObject, pThrowInfo):
        lw.debug("enter _CxxThrowException")
        return
