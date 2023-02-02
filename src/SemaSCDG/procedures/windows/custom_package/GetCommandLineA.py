import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        #self.state.memory.store(0xabcd1234,"./malware") # TODO
        #return 0xabcd1234
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
