import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetKeyboardType(angr.SimProcedure):
    def run(self,nTypeFlag):
        return 0x4
