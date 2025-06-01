import os
import sys
import angr
import logging
try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class strtok(angr.SimProcedure):
    """_summary_
    The strtok() method splits str[] according to given delimiters and returns the next token.
    It needs to be called in a loop to get all tokens. It returns NULL when there are no more tokens.
    Args:
        angr (_type_): _description_
    """
    def run(self, str_ptr, delim_ptr):

        str_object = self.state.mem[str_ptr].string.concrete
        if not str_object:
            lw.debug("str_ptr null, used saved str_ptr")
            str_ptr = self.state.globals.get("strtok_last", None)
            if str_ptr is None:
                lw.debug("No saved str_ptr")
                return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            str_object = self.state.mem[str_ptr].string.concrete

        delim_object = self.state.mem[delim_ptr].string.concrete

        str = str_object.decode()
        delim = delim_object.decode()

        token = ''
        for i in range(0, len(str)):
            if str[i] in delim :
                break
            token += str[i]

        if not token:
            lw.debug("token not found")
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)


        self.state.memory.store(str_ptr, self.state.solver.BVV(token.encode()))
        self.state.memory.store(str_ptr + len(token), self.state.solver.BVV(0, 8))

        self.state.globals["strtok_last"] = str_ptr + len(token) + 1
        lw.debug(repr(self.state.mem[str_ptr].string.concrete))

        return str_ptr