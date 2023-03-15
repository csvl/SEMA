import logging
import angr
import archinfo
lw = logging.getLogger("CustomSimProcedureWindows")

class recv(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if self.state.globals["recv"] > 2:
            return -1
        self.state.globals["recv"] += 1
        if length.symbolic:
            ptr=self.state.solver.BVS("buf",8*0x10)
            self.state.memory.store(buf,ptr)
            retval = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(retval < 0x10)
            self.state.solver.add(retval >= 0)
            return retval
        else:
            ptr=self.state.solver.BVS("buf",8*self.state.solver.eval(length),key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(buf,ptr)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return length
