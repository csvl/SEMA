import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class ShellExecuteExW(angr.SimProcedure):

    def run(
        self,
        pExecInfo
    ):
        return 0x1
