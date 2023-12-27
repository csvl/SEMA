import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

class rand(angr.SimProcedure):
    def run(self):
        lw.info('&'*100)
        lw.info('using custom `random')
        rval = self.state.solver.BVV(0, 32) #rval = self.state.solver.BVS("rand", 31, key=("api", "rand"))
        lw.info(f'int size: {self.arch.sizeof["int"]}')
        lw.info('&'*100)
        return 0 # rval # rval.zero_extend(self.arch.sizeof["int"] - 31) self.state.solver.BVV(0, 32)  # rval.zero_extend(self.arch.sizeof["int"] - 31)
