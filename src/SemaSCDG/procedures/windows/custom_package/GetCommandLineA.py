import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        self.state.memory.store(0xabcd1234,"C:\malware.exe")
        return 0xabcd1234
