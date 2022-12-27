import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class HttpEndRequestA(angr.SimProcedure):
    def run(self, hRequest, lpBuffersOut, dwFlags, dwContext):
        return 0x1
