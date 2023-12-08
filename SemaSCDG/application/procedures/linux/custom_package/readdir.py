import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

class readdir(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self,dirp):
        lw.debug(self.cc)
        return 0
