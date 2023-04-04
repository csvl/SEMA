import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class InternetOpenUrlA(angr.SimProcedure):
    def run(self, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
        print(self.state.mem[lpszUrl].string.concrete)
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle
