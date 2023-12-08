import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class WriteProcessMemory(angr.SimProcedure):

    def run(
        self,
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten
    ):
        x = self.state.solver.eval(nSize)
        self.state.memory.store(lpBaseAddress, self.state.memory.load(lpBuffer,x),size=x)
        return 0x1
