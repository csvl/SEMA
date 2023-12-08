import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class CreateEventA(angr.SimProcedure):

    def run(
        self,
        lpEventAttributes,
        bManualReset,
        bInitialState,
        lpName
    ):
        ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(ret_val > 0x0)
        return ret_val
