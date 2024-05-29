import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.project.simos.acmdln_ptr
