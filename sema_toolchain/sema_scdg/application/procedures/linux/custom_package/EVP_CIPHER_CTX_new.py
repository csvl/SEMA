import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CIPHER_CTX_new(angr.SimProcedure):
    def run(self):
        # initializes cipher contex ctx
        #ctx not useful so every evp_cipher_CTX skipped
        #need to change all evp_cipher_CTX function for really simulated the library.
        return 1