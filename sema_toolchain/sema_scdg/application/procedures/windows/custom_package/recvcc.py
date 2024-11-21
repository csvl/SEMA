import os
import sys


import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)
from claripy import StringS

class recvcc(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        # simfd = self.state.posix.get_fd(s)
        # if simfd is None:
        #     return -1

        # # if length.symbolic:
        # #     pass
        # # else:
        # #     llength = 150 #self.state.solver.eval(length)
        # #     ptr=self.state.solver.BVS("buf",8*llength,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
        # #     self.state.memory.store(buf,ptr)

        # return simfd.read(buf, length)
        if self.state.globals["n_calls_recv"] == 0:
            self.state.globals["n_calls_recv"] = -1
        if length.symbolic:     #TODO heuristique lenght recv
            print("fuck")
            #ptr=self.state.solver.BVS("buf",8*0x50,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            ptr = StringS("buf",size=0x50)
            self.state.memory.store(buf,ptr)
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val != -1)
            self.state.solver.add(ret_val < 0x50)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return ret_val
        elif  self.state.solver.eval(length) > 0x10:
            llength = self.state.solver.eval(length)
            print("llength: " + str(llength))
            #ptr=self.state.solver.BVS("buf",8*0x10,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            ptr = StringS("buf",size=0x10)
            self.state.memory.store(buf,ptr)
            #self.state.solver.add(0x0 in buf)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
        else:
            llength = self.state.solver.eval(length)
            ptr = StringS("buf",size=llength)
            print("llength: " + str(llength))
            #ptr=self.state.solver.BVS("buf",8*llength,key=("buffer", hex(self.state.globals["n_buffer"])),eternal=True)
            print("défé")
            self.state.memory.store(buf,ptr)
            print("data")
            #self.state.solver.add(0x0 in buf)
            self.state.globals["n_buffer"] = self.state.globals["n_buffer"] + 1
            return length
