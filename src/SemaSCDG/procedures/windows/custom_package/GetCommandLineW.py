import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class GetCommandLineW(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        #return self.project.simos.wcmdln_ptr
