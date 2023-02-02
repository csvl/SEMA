import logging
import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

lw = logging.getLogger("CustomSimProcedureWindows")


class FormatMessageW(angr.SimProcedure):
    def run(self, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments):
        """_summary_
        Formats a message string. The function requires a message definition as input. The message definition can come from a 
        buffer passed into the function. It can come from a message table resource in an already-loaded module. Or the caller 
        can ask the function to search the system's message table resource(s) for the message definition. The function finds 
        the message definition in a message table resource based on a message identifier and a language identifier. The function 
        copies the formatted message text to an output buffer, processing any embedded insert sequences if requested.
        """
        ptr=self.state.solver.BVS("lpBuffer",8*self.state.solver.eval(nSize))
        self.state.memory.store(lpBuffer,ptr)
        return self.state.solver.eval(nSize) - 1
