import logging
import sys
import angr
import archinfo

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])

class SizeofResource(angr.SimProcedure):
    def run(self, hModule, hResInfo):
        if self.state.has_plugin("plugin_ressources"):
            if self.state.solver.eval(hResInfo) in self.state.plugin_resources.resources:
                lw.debug(hex(self.state.plugin_resources.resources[self.state.solver.eval(hResInfo)]["size"]))
                return self.state.plugin_resources.resources[self.state.solver.eval(hResInfo)]["size"]
            else:
                return 0x20
                # self.state.solver.BVS(
                #         "retval_{}".format(self.display_name), self.arch.bits
                #     )
        else :
            lw.warning("The procedure SizeofRessource is using the plugin plugin_ressources which is not activated")
