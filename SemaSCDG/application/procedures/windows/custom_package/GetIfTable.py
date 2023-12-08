import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetIfTable(angr.SimProcedure):
    def run(self, pIfTable, pdwSize, bOrder):
        return 0x0
