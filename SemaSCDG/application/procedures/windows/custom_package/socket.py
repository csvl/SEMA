import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class socket(angr.SimProcedure):
    def run(self, af, typee, protocol):
        return 0x1
