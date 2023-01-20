import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class gethostbyname(angr.SimProcedure):
    def run(self, hostname):
        return self.state.solver.BVS("retval_{}".format(self.display_name), 32)
