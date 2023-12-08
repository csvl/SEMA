import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class PathFileExistsA(angr.SimProcedure):
    def run(self, pszPath):
        try:
            print(self.state.mem[pszPath].string.concrete)
        except:
            print(self.state.memory.load(pszPath,0x20))
        return 0x1
