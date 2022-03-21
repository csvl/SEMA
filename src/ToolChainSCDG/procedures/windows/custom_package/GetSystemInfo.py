import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetSystemInfo(angr.SimProcedure):
    def run(self, lpSystemInfo):
        # See Microsoft Doc for more info
        if lpSystemInfo.symbolic:
            return
        sysinfo = self.state.solver.BVS(
            "System_info_{}".format(self.display_name), 36 * 8
        )
        self.state.memory.store(lpSystemInfo, sysinfo)
        dwNumberOfProcessors = self.state.solver.BVS(
            "Number_of_processors_{}".format(self.display_name), 4 * 8
        )
        self.state.memory.store(lpSystemInfo + 20, dwNumberOfProcessors)
        return
