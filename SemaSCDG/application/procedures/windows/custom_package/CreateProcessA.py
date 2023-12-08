import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class CreateProcessA(angr.SimProcedure):

    def run(
        self,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    ):
        processinfo = self.state.solver.BVS("Process_Information_{}".format(self.display_name), 32*4)
        self.state.memory.store(lpProcessInformation, processinfo)
        return 0x1
