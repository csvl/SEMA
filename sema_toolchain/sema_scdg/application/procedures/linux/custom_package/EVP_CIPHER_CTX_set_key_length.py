import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CIPHER_CTX_set_key_length(angr.SimProcedure):
    def run(self, ctx, lenght):
        # sets the key length of the cipher ctx
        return 1