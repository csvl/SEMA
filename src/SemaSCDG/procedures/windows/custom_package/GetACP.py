import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetACP(angr.SimProcedure):
    def run(self):
         ret_expr = self.state.solver.BVV(1252, 32)
         return ret_expr
