import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class RegCreateKeyW(angr.SimProcedure):
    def run(self, hKey, lpSubKey, phkResult):
        lw.debug("RegCreateKeyW.run")
        try:
            subkey = self.state.mem[lpSubKey].wstring.concrete
            lw.debug("subkey: {}".format(subkey))
        except:
            pass
        ptr = self.state.solver.BVS(
            "key_handle_{}".format(self.display_name), self.arch.bits
        )
        self.state.memory.store(phkResult,ptr)

        return 0