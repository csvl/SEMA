import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class setsockopt(angr.SimProcedure):
    def run(self, s, level, optname, optval, optlen):
        return 0x0
