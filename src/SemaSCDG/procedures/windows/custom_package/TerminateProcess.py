import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class TerminateProcess(angr.SimProcedure):
    NO_RET = True
    def run(self, handle, exit_code):
        self.exit(exit_code)
