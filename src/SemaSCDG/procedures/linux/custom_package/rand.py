import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

class rand(angr.SimProcedure):
    def run(self):
        lw.info('&'*100)
        lw.info('using custom `random')
        rval = self.state.solver.BVV(0, 31) #rval = self.state.solver.BVS("rand", 31, key=("api", "rand"))
        lw.info('&'*100)
        return rval.zero_extend(self.arch.sizeof["int"] - 31)