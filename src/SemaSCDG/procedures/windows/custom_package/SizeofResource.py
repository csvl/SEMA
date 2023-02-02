import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class SizeofResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        if self.state.solver.eval(hResInfo) in self.state.globals["resources"]:
            print(hex(self.state.globals["resources"][self.state.solver.eval(hResInfo)]))
            return self.state.globals["resources"][self.state.solver.eval(hResInfo)]
        else:
            return 0x20
           
        
