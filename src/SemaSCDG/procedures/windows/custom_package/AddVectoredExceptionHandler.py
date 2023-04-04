import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class AddVectoredExceptionHandler(angr.SimProcedure):
    def run(
        self,
        First,
        Handler
    ):
        self.state.globals['handler'] = Handler
        self.state.globals['jump'] = 0x4025b3 # TODO
        return 0x1
