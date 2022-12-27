import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InternetOpenA(angr.SimProcedure):
    def run(self, lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags):
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle
