import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))
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
