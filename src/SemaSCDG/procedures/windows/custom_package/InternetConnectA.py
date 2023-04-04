import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InternetConnectA(angr.SimProcedure):
    def run(self, hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext):
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle
