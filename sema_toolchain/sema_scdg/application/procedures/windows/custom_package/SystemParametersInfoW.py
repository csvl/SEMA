import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)
class SystemParametersInfoW(angr.SimProcedure):
    def run(self, uiAction, uiParam, pvParam, fWinIni):
        lw.debug("SystemParametersInfoW called")
        retval = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        return retval

