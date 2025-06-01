import angr
import logging
import os

import claripy

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class CryptImportKey(angr.SimProcedure):
    def run(self, hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey):
        lw.debug("CryptImportKey called")

        key = self.state.solver.BVS("Key_Import", self.arch.bits)
        self.state.memory.store(phKey, key)
        # retval = self.state.solver.BVS(
        #     "retval_{}".format(self.display_name), self.arch.bits
        # )
        # self.state.solver.add(claripy.Or(retval==0, retval==1))
        # return retval
        return 1
