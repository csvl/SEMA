import logging
import time as timer
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetTempFileNameA(angr.SimProcedure):
    def decodeString(self, ptr):
        fileName = self.state.mem[ptr].string.concrete
        return fileName

    def run(self, lpPathName, lpPrefixString, uUnique, lpTempFileName):

        self.state.project
        # import pdb; pdb.set_trace()
        dirname = self.decodeString(lpPathName)
        name = self.decodeString(lpPrefixString)[:3]

        uid = self.state.solver.eval(uUnique)
        if uid == 0:
            uid = int(timer.time())
        hexnum = "{0:0{1}x}".format(uid, 2)

        if hasattr(dirname, "decode"):
            try:
                dirname = dirname.decode("utf-8")
            except:
                dirname = dirname.decode("utf-8",errors="ignore")
        if hasattr(name, "decode"):
            try:
                name = name.decode("utf-8")
            except:
                name = name.decode("utf-8",errors="ignore")

        fd = self.state.posix.open(
            dirname + name + hexnum + ".TMP\0", self.state.solver.BVV(2, self.arch.bits)
        )

        newName = dirname + name + hexnum + ".TMP\0"
        newName = self.state.solver.BVV(newName)
        self.state.memory.store(lpTempFileName, newName)
        # import pdb; pdb.set_trace()

        return int(hexnum, 16)
