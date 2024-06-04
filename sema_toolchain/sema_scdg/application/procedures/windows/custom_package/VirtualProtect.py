import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import logging

from .VirtualAlloc import convert_prot, deconvert_prot

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class VirtualProtect(angr.SimProcedure):
    def run(self, lpAddress, dwSize, flNewProtect, lpfOldProtect):
        return 1
