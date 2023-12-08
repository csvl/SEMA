import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class TerminateProcess(angr.SimProcedure):
    NO_RET = True
    def run(self, handle, exit_code):
        self.exit(exit_code)
