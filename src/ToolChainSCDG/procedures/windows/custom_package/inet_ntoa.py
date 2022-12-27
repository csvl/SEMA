import angr
import logging
lw = logging.getLogger("CustomSimProcedureWindows")

class inet_ntoa(angr.SimProcedure):

    def run(self, addr):
        self.state.memory.store(0x666666,"192.168.1.1")
        return 0x666666
