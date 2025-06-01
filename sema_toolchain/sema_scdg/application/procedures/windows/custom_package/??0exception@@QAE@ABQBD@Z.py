import os
import sys
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class Cpp_Exception(angr.SimProcedure):
    ALT_NAMES = "??0exception@@QAE@ABQBD@Z"
    def run(self,  this_ptr, msg_ptr):
        lw.debug("C++ std::exception constructor called")
        try:
            lw.debug("white error : %s",self.state.mem[msg_ptr].string.concrete)
        except:
            lw.debug("non concrete message")

        return
