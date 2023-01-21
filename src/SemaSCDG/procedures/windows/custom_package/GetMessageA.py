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
        return 1
