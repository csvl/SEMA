import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class DecodePointer(angr.SimProcedure):
    def run(self, ptr):
        lw.info("DecodePointer: Hello")
        return ptr
