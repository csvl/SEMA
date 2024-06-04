import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class FindWindowW(angr.SimProcedure):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].wstring.concrete
        if hasattr(lib, "decode"):
            lib = lib.decode("utf-16-le")
        return lib

    def run(
        self,
        lpClassName,
        lpWindowName
    ):
        className = self.decodeString(lpClassName)
        return 0x0
