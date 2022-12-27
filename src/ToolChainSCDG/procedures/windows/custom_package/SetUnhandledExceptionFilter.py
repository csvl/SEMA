import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class SetUnhandledExceptionFilter(angr.SimProcedure):
    def run(
        self,
        lpTopLevelExceptionFilter
    ):
        self.state.globals['handler'] = lpTopLevelExceptionFilter
        self.state.globals['jump'] = 0x402635
        return 0x1
