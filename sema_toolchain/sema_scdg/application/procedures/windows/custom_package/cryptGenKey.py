import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class CryptGenKey(angr.SimProcedure):
    def run(self, hProv, Algid, dwFlags, phKey):
        lw.debug("CryptGenKey called")
        key = self.state.solver.BVS("key_GenKey", self.arch.bits)
        self.state.memory.store(phKey, key)

        return 1
