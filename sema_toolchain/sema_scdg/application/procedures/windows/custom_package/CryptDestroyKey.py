import os
import sys
import logging
import angr

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class CryptDestroyKey(angr.SimProcedure):
    def run(self, hKey):
        lw.debug("CryptDestroyKey called")
        return 1
