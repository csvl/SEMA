import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class lstrlenA(angr.SimProcedure):
    def run(self, s):
        if s.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)
        
        try:
            string = self.state.mem[s].string.concrete
            return len(string)
        except:
            lw.info("s not resolvable")
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(s+i,1)) == 0x0:
                    return i
            lw.info("can't find length")
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)

