import angr
from angr.sim_type import SimTypeString, SimTypeLength

class wcslen(angr.SimProcedure):
    def run(self, string):
        # Ensure that string is a wide-character string
        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)
        # print("cacacacacac")
        # Use angr's memory access functions to determine the length of the string
        length = self.state.memory.load(string, 4, endness='Iend_LE')
        return length