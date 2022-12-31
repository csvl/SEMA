import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class strcat(angr.SimProcedure):
    def run(self, string1, string2):

        if string1.symbolic or string2.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
        first_str = self.state.mem[string1].string.concrete
        second_str = self.state.mem[string2].string.concrete

        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except:
                first_str = first_str.decode("utf-8",errors="ignore")
        if hasattr(second_str, "decode"):
            try:
                second_str = second_str.decode("utf-8")
            except:
                second_str = second_str.decode("utf-8",errors="ignore")
        new_str = first_str + second_str + "\0"

        len_s = len(second_str)
        src = self.state.memory.load(string2,len_s,endness='Iend_BE')
        self.state.memory.store(string1+len(first_str),src,endness='Iend_BE')

        self.arguments = [first_str,second_str]
        self.ret_expr = first_str
        return string1
