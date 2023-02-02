import angr
import logging

from .VirtualAlloc import convert_prot, deconvert_prot

l = logging.getLogger(name=__name__)

class VirtualProtect(angr.SimProcedure):
    def run(self, lpAddress, dwSize, flNewProtect, lpfOldProtect):
        return 1
