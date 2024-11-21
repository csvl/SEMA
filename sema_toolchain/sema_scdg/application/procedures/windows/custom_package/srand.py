import os
import sys


import angr


class srand(angr.SimProcedure):
    def run(self, seed):
        print("caca")
        #self.ret()
        return
