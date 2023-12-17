import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class HttpEndRequestA(angr.SimProcedure):
    def run(self, hRequest, lpBuffersOut, dwFlags, dwContext):
        return 0x1
