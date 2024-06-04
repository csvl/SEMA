import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .GetTempFileNameA import GetTempFileNameA


class GetTempFileNameW(GetTempFileNameA):
    def decodeString(self, ptr):
        fileName = self.state.mem[ptr].wstring.concrete
        return fileName
