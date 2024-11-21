import os
import sys


import logging
import angr
import claripy
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class CryptGetHashParam(angr.SimProcedure):
    def run(
        self,
        hHash,
        dwParam,
        pbData,
        pdwDataLen,
        dwFlags
    ):
        ptr1 = claripy.BVV(0x10, self.arch.bits)
        self.state.memory.store(pdwDataLen,ptr1)
        ptr = claripy.BVV(self.state.globals["crypt_result"])
        self.state.memory.store(pbData,ptr)
        return 0x1
