import logging
from .TlsAlloc import TlsAlloc

lw = logging.getLogger("CustomSimProcedureWindows")


class FlsAlloc(TlsAlloc):
    KEY = "win32_fls"

    def run(self, callback):
        if not self.state.solver.is_true(callback == 0):
            # raise angr.errors.SimValueError("Can't handle callback function in FlsAlloc")
            lw.info("FlsAlloc: Callback specified")
        return super(FlsAlloc, self).run()
