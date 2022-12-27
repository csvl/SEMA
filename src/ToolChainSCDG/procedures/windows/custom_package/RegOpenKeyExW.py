import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class RegOpenKeyExW(angr.SimProcedure):

    def run(
        self,
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    ):
        return 0x0
