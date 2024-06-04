import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .GetUserNameA import GetUserNameA


class GetUserNameW(GetUserNameA):
    def get_username(self, size):
        return ("CharlyBVO"[: size - 1] + "\0").encode("utf-16-le")
