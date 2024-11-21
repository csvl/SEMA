import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class RegOpenKeyExA(angr.SimProcedure):

    def run(
        self,
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    ):
        ptr = self.state.solver.BVS(
            "key_handle_{}".format(self.display_name), self.arch.bits
        )
        self.state.memory.store(phkResult,ptr)
        return 0x0
