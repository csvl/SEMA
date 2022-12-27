import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class GetCommandLineW(angr.SimProcedure):
    def run(self):
        self.state.memory.store(0x666666,"./malware")
        return 0x666666
