import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetACP(angr.SimProcedure):
    def run(self):
         ret_expr = self.state.solver.BVV(1252,  self.arch.bits)
         return ret_expr
