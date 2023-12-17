import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


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
