import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class EVP_CipherInit_ex(angr.SimProcedure):
    def run(self, ctx, type, impl, key, iv, enc):
        # init ctx for decryption or encryption
        # enc = 1 for encrypt
        # enc = 0 decrypt
        return 0