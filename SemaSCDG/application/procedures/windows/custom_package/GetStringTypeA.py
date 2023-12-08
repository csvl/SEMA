import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetStringTypeA(angr.SimProcedure):
    def run(self, dwInfoType, lpSrcStr, cchSrc, lpCharType):
        return 1
