import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class socket(angr.SimProcedure):
    def run(self, af, typee, protocol):
        return 0x1
