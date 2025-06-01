import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_bf_cbc(angr.SimProcedure):
    def run(self):
        # encryption algorithm
        return 1