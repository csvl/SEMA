import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class RegSetValueExA(angr.SimProcedure):
    def run(
        self,
        hKey,
        lpValueName,
        lpReserved,
        lpType,
        lpData,
        cbData
    ):
        return 0x0
