import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CreateProcessW(angr.SimProcedure):

    def run(
        self,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    ):
        processinfo = self.state.solver.BVS("Process_Information{}".format(self.display_name), 32*4)
        lw.info(lpCommandLine)
        lw.info(lpApplicationName)
        self.state.memory.store(lpProcessInformation, processinfo)
        return 0x1
