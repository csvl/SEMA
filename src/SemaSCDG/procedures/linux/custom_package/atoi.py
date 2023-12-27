import angr
from .open import open

import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")


# should be safe bc gonnacry doesn't use fields of DIR *
class atoi(angr.SimProcedure):
    def run(self, s_addr):
        # load string from address... how do i do this?
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        s_strlen = self.inline_call(strlen, s_addr)
        p_expr = self.state.memory.load(
            s_addr, s_strlen.max_null_index, endness="Iend_BE"
        )
        string = self.state.solver.eval(p_expr, cast_to=bytes).decode()
        lw.info('Using atoi found the string '+string)
        return int(string)