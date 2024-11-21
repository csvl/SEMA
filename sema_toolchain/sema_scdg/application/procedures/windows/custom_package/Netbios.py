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


class Netbios(angr.SimProcedure):
    def run(
        self,
        pncb
    ):
        return 0x0
