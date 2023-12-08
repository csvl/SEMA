import logging
import angr
lw = logging.getLogger("LinuxSimProcedure")


class getcwd(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVS("retval_{}".format(self.display_name), 32)

