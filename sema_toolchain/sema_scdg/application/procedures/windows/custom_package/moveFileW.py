import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class MoveFileW(angr.SimProcedure):
    def run(self, lpExistingFileName, lpNewFileName):
        lw.debug("MoveFileW called")
        return 1
