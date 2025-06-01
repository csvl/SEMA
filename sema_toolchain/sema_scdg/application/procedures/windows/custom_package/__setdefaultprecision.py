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


class __setdefaultprecision(angr.SimProcedure):
    def run(self, ):
        lw.debug("enter __setdefaultprecision")
        return
