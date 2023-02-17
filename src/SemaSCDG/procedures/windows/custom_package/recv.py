import logging
import angr
import archinfo
lw = logging.getLogger("CustomSimProcedureWindows")
from claripy import StringS

class recv(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if self.state.globals["n_calls_recv"] == 0:
            self.state.globals["n_calls_recv"] = -1
        if length.symbolic:
            ptr=self.state.solver.BVS("buf",8*0x20,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(buf,ptr)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val != -1)
            self.state.solver.add(ret_val < 0x20)
            return ret_val
        # elif self.state.solver.eval(length) > 0x20:
        #     ptr=self.state.solver.BVS("buf",8*0x20,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
        #     self.state.memory.store(buf,ptr,endness=archinfo.Endness.LE)
        #     self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
        #     return 0x20
        else:
            ptr=self.state.solver.BVS("buf",8*self.state.solver.eval(length),key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(buf,ptr)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return length
