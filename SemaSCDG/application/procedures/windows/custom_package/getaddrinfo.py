import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class getaddrinfo(angr.SimProcedure):
    def run(self, pNodeName, pServiceName, pHints, ppResult):
        return 0x0
