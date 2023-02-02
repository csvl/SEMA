import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class lstrcatA(angr.SimProcedure):
    def run(self, string1, string2):
        # import pdb; pdb.set_trace()
        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        try:
            first_str = self.state.mem[string1].string.concrete
        except:
            first_str = self.state.solver.eval(string1)
        try:
            second_str = self.state.mem[string2].string.concrete
        except:
            second_str = self.state.solver.eval(string2)
        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except (UnicodeDecodeError):
                first_str = ""
        if hasattr(second_str, "decode"):
            try:
                second_str = second_str.decode("utf-8")
            except (UnicodeDecodeError):
                second_str = ""
        new_str = first_str + second_str + "\0"
        new_str = self.state.solver.BVV(new_str)
        self.state.memory.store(string1, new_str)  # ,endness=self.arch.memory_endness)

        return string1
