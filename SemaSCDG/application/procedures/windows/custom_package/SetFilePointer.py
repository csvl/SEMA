import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class SetFilePointer(angr.SimProcedure):
    def run(self, hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod):
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ret_val > 0)
        return ret_val
