import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class atoi(angr.SimProcedure):
    def run(self, string):
        # import pdb; pdb.set_trace()
        if string.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        second_str = self.state.solver.eval(string)
        print(second_str)
        return second_str
