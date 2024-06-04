import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .GetComputerNameA import GetComputerNameA


class GetComputerNameW(GetComputerNameA):
    def get_username(self, size):
        return ("CharlyBVO_PC"[: size - 1] + "\0").encode("utf-16-le")
