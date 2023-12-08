import logging
import sys
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))

class LCMapStringA(angr.SimProcedure):
    def run(self, Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest):
        return cchSrc
