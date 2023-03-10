import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


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
