import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class InitCommonControlsEx(angr.SimProcedure):
    def run(self, ptr):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
