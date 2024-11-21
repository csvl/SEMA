import os
import sys


import angr


class EncodePointer(angr.SimProcedure):
    def run(self, ptr):
        return ptr
