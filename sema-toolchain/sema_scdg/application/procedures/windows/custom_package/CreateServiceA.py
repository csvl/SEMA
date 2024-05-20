import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class CreateServiceA(angr.SimProcedure):

    def run(
        self,
        hSCManager,
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        lpBinaryPathName,
        lpLoadOrderGroup,
        lpdwTagId,
        lpDependencies,
        lpServiceStartName,
        lpPassword
    ):
        retval = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(retval != 0x0)
        return retval
