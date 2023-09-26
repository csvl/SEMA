import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

class getuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        lw.info(self.cc)
        return 1000
