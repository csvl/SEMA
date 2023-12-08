import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetDriveTypeA(angr.SimProcedure):
    def run(self, lpRootPathName):
        return 0x3
