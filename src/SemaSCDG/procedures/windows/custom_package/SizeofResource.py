import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class SizeofResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        val = self.state.solver.eval(hResInfo)
        lw.info("hResInfo: {}".format(val))
        if val in self.state.globals["resources"]:
            print(hex(self.state.globals["resources"][val]))
            return self.state.globals["resources"][val]
        else:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
           
        
