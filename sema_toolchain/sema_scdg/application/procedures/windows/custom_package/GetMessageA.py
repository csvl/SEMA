import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


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
