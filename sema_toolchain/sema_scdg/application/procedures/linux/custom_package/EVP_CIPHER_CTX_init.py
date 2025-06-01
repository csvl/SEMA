import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CIPHER_CTX_init(angr.SimProcedure):
    def run(self, ctx):
        # creates a cipher context
        return 1