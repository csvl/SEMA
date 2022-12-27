import logging
import angr
import claripy
lw = logging.getLogger("CustomSimProcedureWindows")


class RtlGetVersion(angr.SimProcedure):
    def run(
        self, lpVersionInformation
    ):
        versioninfo = self.state.solver.BVS("Version_Info{}".format(self.display_name), 8*148)
        self.state.memory.store(lpVersionInformation,versioninfo)
        return 0x0
