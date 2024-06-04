import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .GetModuleHandleExW import GetModuleHandleExW


class GetModuleHandleExA(GetModuleHandleExW):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].string.concrete.decode("utf-8")
        return lib
