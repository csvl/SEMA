import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class CreateProcessW(angr.SimProcedure):

    def run(
        self,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    ):
        processinfo = self.state.solver.BVS("Process_Information_{}".format(self.display_name), 32*4)
        self.state.memory.store(lpProcessInformation, processinfo)
        return 0x1
