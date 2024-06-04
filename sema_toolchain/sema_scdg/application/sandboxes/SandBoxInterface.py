import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
class SandBoxInterface:
    def __init__(self, host="127.0.0.1", port=8000, proto="http") -> None:
        pass
