import angr
import logging
import os

lw = logging.getLogger("CustomSimProcedureLinux")
lw.setLevel(os.environ["LOG_LEVEL"])

class getuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        lw.debug(self.cc)
        return 1000
