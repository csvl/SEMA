import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class lstrcpyA(angr.SimProcedure):
    def run(self, lpstring1, lpstring2):
        if lpstring1.symbolic or lpstring2.symbolic:
            return lpstring1  # self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)
        # first_str = self.state.mem[string1].string.concrete
        second_str = self.state.mem[lpstring2].string.concrete
        # if hasattr(first_str,'decode'):
        #   first_str= first_str.decode('utf-8')
        if isinstance(second_str, str):
            new_str = second_str + "\0"
        else:
            new_str = second_str + b"\0"

        new_str = self.state.solver.BVV(new_str)
        self.state.memory.store(
            lpstring1, new_str
        )  # ,endness=self.arch.memory_endness)
        # import pdb; pdb.set_trace()
        return lpstring1
