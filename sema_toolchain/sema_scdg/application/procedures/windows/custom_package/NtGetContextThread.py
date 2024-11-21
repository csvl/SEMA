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


class NtGetContextThread(angr.SimProcedure):
    def run(
        self,
        ThreadHandle,
        pContext
    ):
        return 0x0
