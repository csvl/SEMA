import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SHBrowseForFolder(angr.SimProcedure):
    def run(self, arg1):
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
