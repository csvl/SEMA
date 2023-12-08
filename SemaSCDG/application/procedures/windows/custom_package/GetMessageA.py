import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetMessageA(angr.SimProcedure):

    def run(
        self,
        lpMsg,
        hWnd,
        wMsgFilterMin,
        wMsgFilterMax
    ):
        if self.state.globals["GetMessageA"] == 0:
            self.state.globals["GetMessageA"] = 1
            return 1
        else:
            return 0
