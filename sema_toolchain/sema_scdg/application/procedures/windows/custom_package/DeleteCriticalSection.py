import os
import sys


import angr


class DeletCriticalSection(angr.SimProcedure):
    def run(self, addr):
        #self.ret()
        return
