import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class HttpSendRequestA(angr.SimProcedure):
    def run(self, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
        return 0x1
