import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class LookupPrivilegeValueA(angr.SimProcedure):
    def run(
        self,
        lpSystemName,
        lpName,
        lpLuid
    ):
        return 0x1
