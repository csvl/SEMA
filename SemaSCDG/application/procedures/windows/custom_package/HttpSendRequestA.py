import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class HttpSendRequestA(angr.SimProcedure):
    def run(self, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
        return 0x1
