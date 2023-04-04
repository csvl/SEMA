import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.project.simos.acmdln_ptr
