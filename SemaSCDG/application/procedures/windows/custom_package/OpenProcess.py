import logging
import angr
import archinfo
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class OpenProcess(angr.SimProcedure):
    def run(self, dwDesiredAccess, bInheritHandle, dwProcessId):
        retval = self.state.solver.BVS("retval{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(retval != 0)
        return retval
