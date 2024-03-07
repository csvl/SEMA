import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])
import requests

class URLDownloadToFileA(angr.SimProcedure):

    def run(
        self,
        pCaller,
        szURL,
        szFileName,
        dwReserved,
        lpfnCB
    ):
        lw.debug("URLDownloadToFileA called")
        if self.state.globals["allow_web_interaction"]:
            url = self.state.memory[szURL].string.concrete
            r = requests.get(url, allow_redirects=True)
        return 0x0
