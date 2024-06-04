import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .CreateFileA import CreateFileA


class CreateFileW(CreateFileA):
    def decodeString(self, ptr):
        filename = self.state.mem[ptr].wstring.concrete
        # if hasattr(filename, "decode"):
        #     filename = filename.decode("utf-8","ignore")
        return filename
