import logging
from .TlsAlloc import TlsAlloc

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class FlsAlloc(TlsAlloc):
    KEY = "win32_fls"

    def run(self, callback):
        if not self.state.solver.is_true(callback == 0):
            # raise angr.errors.SimValueError("Can't handle callback function in FlsAlloc")
            lw.debug("FlsAlloc: Callback specified")
        return super(FlsAlloc, self).run()
