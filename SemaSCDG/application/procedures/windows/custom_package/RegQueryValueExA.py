import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegQueryValueExA(angr.SimProcedure):
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
