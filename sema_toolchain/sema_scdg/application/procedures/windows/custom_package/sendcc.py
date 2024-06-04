import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class sendcc(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if self.state.globals["n_calls_send"] == 0:
            self.state.globals["n_calls_send"] = -1
        if length.symbolic:
            # ptr=self.state.solver.BVS("buf",8*0x10,key=("buffer_send", hex(self.state.globals["n_buffer_send"])),eternal=True)
            # self.state.memory.store(buf,ptr)
            # self.state.globals["buffer_send"] = self.state.memory.load(buf,l)
            # self.state.globals["n_buffer_send"] = self.state.globals["n_buffer_send"] + 1
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        else:
            l = self.state.solver.eval(length)
            lw.debug("lenght: " + str(l))
            # ptr=self.state.solver.BVS("buf",8*self.state.solver.eval(length),key=("buffer_send", hex(self.state.globals["n_buffer_send"])),eternal=True)
            # self.state.memory.store(buf,ptr)
            if len(self.state.globals["buffer_send"]) == 0:
                self.state.globals["buffer_send"] = [(buf,l)]
            else:
                self.state.globals["buffer_send"].append((buf,l))
            self.state.globals["n_buffer_send"] = self.state.globals["n_buffer_send"] + 1
            lw.debug(hex(self.state.solver.eval(self.state.memory.load(buf,l))))
            return l
            ptr=self.state.solver.BVS("buf",8*self.state.solver.eval(length),key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            self.state.memory.store(buf,ptr)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return length
