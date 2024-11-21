import os
import sys


import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class LookupPrivilegeValueA(angr.SimProcedure):
    def run(
        self,
        lpSystemName,
        lpName,
        lpLuid
    ):
        return 0x1
