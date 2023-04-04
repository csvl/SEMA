import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InternetCloseHandle(angr.SimProcedure):
    def run(self, hInternet):
        return 0x1
