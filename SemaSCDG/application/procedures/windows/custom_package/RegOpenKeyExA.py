import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class RegOpenKeyExA(angr.SimProcedure):

    def run(
        self,
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    ):
        ptr = self.state.solver.BVS(
            "key_handle_{}".format(self.display_name), self.arch.bits
        )
        self.state.memory.store(phkResult,ptr)
        return 0x0
