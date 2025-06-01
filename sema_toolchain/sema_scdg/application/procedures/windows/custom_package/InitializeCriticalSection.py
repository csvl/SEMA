import os
import sys


import angr


class InitializeCriticalSection(angr.SimProcedure):
    def run(self, addr):
        #self.ret()
        return
