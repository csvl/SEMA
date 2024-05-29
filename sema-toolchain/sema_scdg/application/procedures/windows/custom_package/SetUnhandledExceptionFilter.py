import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class SetUnhandledExceptionFilter(angr.SimProcedure):
    def run(
        self,
        lpTopLevelExceptionFilter
    ):
        self.state.globals['handler'] = lpTopLevelExceptionFilter
        self.state.globals['jump'] = 0x402635
        return 0x1
