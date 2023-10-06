import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class setsockopt(angr.SimProcedure):
    def run(self, s, level, optname, optval, optlen):
        return 0x0
