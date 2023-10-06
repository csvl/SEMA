import logging
import angr
import archinfo
lw = logging.getLogger("CustomSimProcedureWindows")


class OpenProcess(angr.SimProcedure):
    def run(self, dwDesiredAccess, bInheritHandle, dwProcessId):
        retval = self.state.solver.BVS("retval{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(retval != 0)
        return retval
