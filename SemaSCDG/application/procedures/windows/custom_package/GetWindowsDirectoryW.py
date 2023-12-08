import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetWindowsDirectoryW(angr.SimProcedure):
    def run(self, lpBuffer, uSize):
        size = self.state.solver.eval(uSize)
        path = self.state.solver.BVV(b'C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\x00\x00')
        self.state.memory.store(lpBuffer, path)
        return 20
