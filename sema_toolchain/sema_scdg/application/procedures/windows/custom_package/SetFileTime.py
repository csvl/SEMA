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


class SetFileTime(angr.SimProcedure):
    def run(self, hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime):
        lw.debug("SetFileTime.run")
        try:
            path = self.state.mem[hFile].wstring.concrete
            lw.debug("path: {}".format(path))
        except:
            pass
        return 1

