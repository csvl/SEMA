import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetACP(angr.SimProcedure):
    def run(self):
         ret_expr = self.state.solver.BVV(1252,  self.arch.bits)
         return ret_expr
