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


class SystemTimeToFileTime(angr.SimProcedure):
    def run(self, lpSystemTime, lpFileTime):
        lw.debug("SystemTimeToFileTime.run")
        time = self.state.memory.load(lpSystemTime,16)
        self.state.memory.store(lpFileTime, time[0:8],8)
        return 1