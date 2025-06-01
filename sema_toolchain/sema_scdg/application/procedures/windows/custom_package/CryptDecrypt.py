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

class CryptDecrypt(angr.SimProcedure):
    def run(self, hKey, hHash, Final, dwFlags, pbData, pdwDataLen):
        lw.debug("CryptDecrypt called")
        if self.state.solver.symbolic(hKey):
            key = self.state.solver.BVS("Key_Decrypt", self.arch.bits)
            self.state.store(hKey, key)
        len = self.state.solver.BVV(self.arch.bits,self.arch.bits)
        self.state.memory.store(pdwDataLen, len, endness='Iend_LE')

        return 1
