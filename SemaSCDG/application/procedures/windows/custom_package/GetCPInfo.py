import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetCPInfo(angr.SimProcedure):
    def run(self, CodePage,lpCPInfo):
        return 0x1
