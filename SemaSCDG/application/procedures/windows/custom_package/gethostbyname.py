import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class gethostbyname(angr.SimProcedure):
    def run(self, hostname):
        try:
            lw.debug(self.state.mem[hostname].string.concrete)
        except:
            lw.debug(self.state.memory.load(hostname,0x20))
        return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
