import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


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
