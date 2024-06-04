import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .GetSystemInfo import GetSystemInfo

class GetNativeSystemInfo(GetSystemInfo):
    pass
