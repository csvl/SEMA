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


class CoCreateInstance(angr.SimProcedure):
    def run(
        self,
        rclsid,
        pUnkOuter,
        dwClsContext,
        riid,
        ppv
    ):
        print(self.state.memory.load(self.state.solver.eval(rclsid),0x10))
        import archinfo
        print(self.state.memory.load(self.state.solver.eval(rclsid),0x10,endness=archinfo.Endness.LE))
        return -1  # force fail pcq sinon ça fait toujours tout planter a cause des trucs com
