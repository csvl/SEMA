import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetLastError(angr.SimProcedure):
    def run(self):
        #ret_expr = self.state.plugin_env_var.last_error
        # self.state.memory.load(self.state.regs.esp,4,endness= self.arch.memory_endness)
        #return ret_expr
        return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
