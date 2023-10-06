import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InitCommonControls(angr.SimProcedure):
    def run(self):
        pass
