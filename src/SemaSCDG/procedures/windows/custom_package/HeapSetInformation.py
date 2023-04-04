import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class HeapSetInformation(angr.SimProcedure):
    def run(self, HeapHandle, HeapInformationClass, HeapInformation, HeapInformationLength):
        return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
