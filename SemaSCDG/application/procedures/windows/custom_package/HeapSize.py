import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class HeapSize(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem):
        return self.state.globals["HeapSize"][self.state.solver.eval(lpMem)]
