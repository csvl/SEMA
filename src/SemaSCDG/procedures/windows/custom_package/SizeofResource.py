import logging
import sys
import angr
import archinfo

lw = logging.getLogger("CustomSimProcedureWindows")

class SizeofResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        if self.state.solver.eval(hResInfo) in self.state.plugin_resources.resources:
            lw.info(hex(self.state.plugin_resources.resources[self.state.solver.eval(hResInfo)]["size"]))
            return self.state.plugin_resources.resources[self.state.solver.eval(hResInfo)]["size"]
        else:
            return 0x20 
            # self.state.solver.BVS(
            #         "retval_{}".format(self.display_name), self.arch.bits
            #     )
           
        
