import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class wsprintfA(angr.SimProcedure):
    def getVarString(self, ptr):
        string = self.state.mem[ptr].string.concrete
        if hasattr(string, "decode"):
            try:
                string = string.decode("utf-8")
            except:
                string = string.decode("utf-8",errors="ignore")
        return string

    def run(self, arg1, arg2):

        # import pdb; pdb.set_trace()
        lw.info("wsprintfA: " + str(self.arguments))

        if arg1.symbolic or arg2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        var_string = self.getVarString(arg2)
        n_arg = var_string.count("%")
        sup_args = []
        for i in range(1, n_arg + 1):
            sup_args.append(
                self.state.mem[self.state.regs.esp + 8 + 4 * i].int.resolved
            )
            # import pdb; pdb.set_trace()
        self.arguments = self.arguments + sup_args
        new_str = self.state.solver.BVV(var_string)
        self.state.memory.store(arg1, new_str)
        # import pdb; pdb.set_trace()

        return len(var_string)
