import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .GetModuleHandleW import GetModuleHandleW


class GetModuleHandleA(GetModuleHandleW):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].string.concrete
        if hasattr(lib, "decode"):
            lib = lib.decode("utf-8")
        return lib
