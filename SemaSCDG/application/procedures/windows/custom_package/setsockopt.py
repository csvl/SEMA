import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class setsockopt(angr.SimProcedure):
    def run(self, s, level, optname, optval, optlen):
        return 0x0
