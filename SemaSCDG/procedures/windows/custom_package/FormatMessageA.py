import logging
import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

lw = logging.getLogger("CustomSimProcedureWindows")


class FormatMessageA(angr.SimProcedure):
    def run(self, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments):
        ptr=self.state.solver.BVS("lpBuffer",8*self.state.solver.eval(nSize))
        self.state.memory.store(lpBuffer,ptr)
        return self.state.solver.eval(nSize) - 1
