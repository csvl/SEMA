import logging

import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class HttpOpenRequestA(angr.SimProcedure):
    def run(self, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext):
        print(self.state.mem[lpszObjectName].string.concrete)
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle
