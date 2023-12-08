import logging
import time as timer
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class QueryPerformanceCounter(angr.SimProcedure):
    def run(self, ptr):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            val = int(timer.perf_counter() * 1000000) + 12345678
            self.state.mem[ptr].qword = val
        else:
            self.state.mem[ptr].qword = self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        return 1
