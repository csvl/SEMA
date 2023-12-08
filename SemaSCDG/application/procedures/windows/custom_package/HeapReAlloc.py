import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class HeapReAlloc(angr.SimProcedure):
    def run(self, hHeap, dwFlags, lpMem, dwBytes):
        self.state.globals["HeapSize"][self.state.solver.eval(lpMem)] = dwBytes
        return self.state.heap._realloc(lpMem, dwBytes)
