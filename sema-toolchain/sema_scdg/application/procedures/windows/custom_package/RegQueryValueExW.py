import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class RegQueryValueExW(angr.SimProcedure):
    def run(
        self,
        hKey,
        lpValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    ):
        return 0x0
