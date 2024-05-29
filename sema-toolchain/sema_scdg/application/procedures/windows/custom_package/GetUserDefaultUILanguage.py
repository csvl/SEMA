import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetUserDefaultUILanguage(angr.SimProcedure):

    def run(self):
        return 0x1400
