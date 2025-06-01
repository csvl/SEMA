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


class LocalFileTimeToFileTime(angr.SimProcedure):
    def run(self, lpLocalFileTime, lpFileTime):
        lw.debug("LocalFileTimeToFileTime.run")
        self.state.memory.store(lpFileTime, self.state.memory.load(lpLocalFileTime, 8))
        return 1
