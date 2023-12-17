import logging
import angr

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class CreateWindowExA(angr.SimProcedure):

    def run(
        self,
        dwExStyle,
        lpClassName,
        lpWindowName,
        dwStyle,
        X,
        Y,
        nWidth,
        nHeight,
        hWndParent,
        hMenu,
        hInstance,
        lpParam
    ):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
