import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class HttpSendRequestA(angr.SimProcedure):
    def run(self, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
        return 0x1
