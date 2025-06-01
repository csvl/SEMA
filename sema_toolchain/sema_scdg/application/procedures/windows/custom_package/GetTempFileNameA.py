import os
import sys


import logging
import time as timer
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class GetTempFileNameA(angr.SimProcedure):
    def decodeString(self, ptr):
        fileName = self.state.mem[ptr].string.concrete
        return fileName

    def run(self, lpPathName, lpPrefixString, uUnique, lpTempFileName):
        lw.debug("GetTempFileNameA")
        lw.debug(lpPathName)
        if self.state.solver.symbolic(lpPathName) or  self.state.solver.eval(lpPathName) == 0:
            lw.debug("symbolic pathname")
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)

        # import pdb; pdb.set_trace()
        dirname = self.decodeString(lpPathName)
        name = self.decodeString(lpPrefixString)[:3]

        uid = self.state.solver.eval(uUnique)
        if uid == 0:
            uid = int(timer.time())
        hexnum = "{0:0{1}x}".format(uid, 2)

        if hasattr(dirname, "decode"):
            dirname = dirname.decode("utf-8")
        if hasattr(name, "decode"):
            name = name.decode("utf-8")

        fd = self.state.posix.open(
            dirname + name + hexnum + ".TMP\0", self.state.solver.BVV(2, self.arch.bits)
        )

        newName = dirname + name + hexnum + ".TMP\0"
        newName = self.state.solver.BVV(newName)
        self.state.memory.store(lpTempFileName, newName)
        # import pdb; pdb.set_trace()

        return int(hexnum, 16)
