import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class recv(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if self.state.globals["n_calls"] == 0:
            self.state.globals["n_calls"] = -1
        if length.symbolic: #TODO heuristique lenght recv
            ptr=self.state.solver.BVS("buf",8*0x10,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(buf,ptr)
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val > 0)
            self.state.solver.add(ret_val < 0x10)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return ret_val
           
        else:
            ptr=self.state.solver.BVS("buf",8*self.state.solver.eval(length),key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(buf,ptr)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return length
