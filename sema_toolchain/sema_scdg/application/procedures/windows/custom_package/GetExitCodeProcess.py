import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class GetExitCodeProcess(angr.SimProcedure):
    def run(self, hProcess, lpExitCode):
        lw.debug("GetExitCodeProcess.run")
        exit_code = self.state.solver.BVS(
            "lpExitCode", self.arch.bits
        )
        self.state.memory.store(lpExitCode, exit_code)
        return 1
