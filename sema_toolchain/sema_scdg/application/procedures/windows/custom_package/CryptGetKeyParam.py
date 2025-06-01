import logging
import angr
import os

import claripy

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class CryptGetKeyParam(angr.SimProcedure):
    def run(self, hKey, dwParam, pbData, pdwDataLen, dwFlags):
        lw.debug("CryptGetKeyParam called")
        key_param = self.state.solver.BVS("KEY_PARAM", self.arch.bits)
        self.state.memory.store(pbData, key_param)
        self.state.memory.store(pdwDataLen, self.arch.bits,endness='Iend_LE')

        # retval = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        # self.state.solver.add(claripy.Or(retval == 0, retval == 1))
        return 1
