import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging

import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class HttpOpenRequestA(angr.SimProcedure):
    def run(self, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext):
        print(self.state.mem[lpszObjectName].string.concrete)
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle
