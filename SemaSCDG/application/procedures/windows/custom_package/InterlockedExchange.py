import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class InterlockedExchange(angr.SimProcedure):
    def run(self, target, value):
        retval = self.state.mem[target].long.concrete
        self.state.memory.store(target, value, endness=self.arch.memory_endness)
        return retval
