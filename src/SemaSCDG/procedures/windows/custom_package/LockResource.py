import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class LockResource(angr.SimProcedure):
    def run(self, hResData):
        return hResData
           
        
