import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class ThunRTMain(angr.SimProcedure):
    def run(self,address_VB):
        import pdb
        pdb.set_trace()
        return 0x0
