import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class LookupPrivilegeValueA(angr.SimProcedure):
    def run(
        self,
        lpSystemName,
        lpName,
        lpLuid
    ):
        return 0x1
