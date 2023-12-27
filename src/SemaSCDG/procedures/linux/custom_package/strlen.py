import logging
import angr
lw = logging.getLogger("CustomSimProcedureLinux")


class strlen(angr.SimProcedure):
    def run(self, s):
        if s.symbolic:
            lw.info("s is symbolic")
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        
        try:
            string = self.state.mem[s].string.concrete
            lw.info("s is concrete")
            lw.info(string)
            return len(string)
        except:
            lw.info("s not resolvable")
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(s+i,1)) == 0x0:
                    lw.info("found length")
                    lw.info(i)
                    return i
            lw.info("can't find length")
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)

