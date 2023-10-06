import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


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
