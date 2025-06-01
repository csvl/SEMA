
import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CIPHER_CTX_reset(angr.SimProcedure):
    def run(self, ctx):
        # Clears all information from a cipher context and free up any allocated memory associated with it
        # Possibly same function than EVP_CIPHER_CTX_cleanup
        return 1