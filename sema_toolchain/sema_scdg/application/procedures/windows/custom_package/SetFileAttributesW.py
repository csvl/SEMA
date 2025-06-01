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


class SetFileAttributesW(angr.SimProcedure):
    def run(self, lpFileName, dwFileAttributes):
        lw.debug("SetFileAttributesW.run")
        try:
            path = self.state.mem[lpFileName].wstring.concrete
            lw.debug("path: {}".format(path))
        except:
            pass
        return 1
