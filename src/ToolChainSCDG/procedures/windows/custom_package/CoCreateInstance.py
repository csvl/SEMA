import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class CoCreateInstance(angr.SimProcedure):
    def run(
        self,
        rclsid,
        pUnkOuter,
        dwClsContext,
        riid,
        ppv
    ):
        return -1
