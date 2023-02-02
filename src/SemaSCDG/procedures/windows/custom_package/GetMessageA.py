import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


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
