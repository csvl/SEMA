import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class LoadResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        return hResInfo
           
        
