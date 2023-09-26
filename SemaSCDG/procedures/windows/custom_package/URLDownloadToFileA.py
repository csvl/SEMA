import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")
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
        lw.info("URLDownloadToFileA called")
        if self.state.globals["allow_web_interaction"]:
            url = self.state.memory[szURL].string.concrete
            r = requests.get(url, allow_redirects=True)
        return 0x0
