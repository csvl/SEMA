import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class InterlockedIncrement(angr.SimProcedure):
    def run(self, ptr):
        return self.state.mem[ptr].long.concrete + 1
