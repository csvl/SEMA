import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class URLDownloadToFileW(angr.SimProcedure):

    def run(
        self,
        pCaller,
        szURL,
        szFileName,
        dwReserved,
        lpfnCB
    ):
        return 0x0
