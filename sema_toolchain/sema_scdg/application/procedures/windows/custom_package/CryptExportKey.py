import os
import sys

import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class CryptExportKey(angr.SimProcedure):
    def run(
        self,
        hKey,
        hExpKey,
        dwBlobType,
        dwFlags,
        pbData,
        pdwDataLen
    ):
        lw.debug("CryptExportKey")
        self.state.memory.store(pdwDataLen, self.arch.bits, endness='Iend_LE')

        if self.state.solver.eval(pbData):
            key = self.state.solver.BVS("Key_Export", self.arch.bits)
            lw.debug("using key {}".format(key))
            self.state.memory.store(pbData, key)

        return 1