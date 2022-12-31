import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SysAllocString(angr.SimProcedure):
    def run(self, strIn):
        if strIn.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        string_addr = self.state.solver.eval(strIn)
        string = self.state.mem[string_addr].wstring.concrete
        len_str = len(str(string))

        ptr = self.state.heap.malloc(len_str + 1)
        if hasattr(string, "decode"):
            try:
                str_BVV = string.decode("utf-8") + "\0"
            except:
                str_BVV = string.decode("utf-8",errors="ignore") + "\0"
        else:
            str_BVV = string + "\0"

        self.state.memory.store(ptr, str_BVV)  # ,endness=self.arch.memory_endness)
        return ptr
