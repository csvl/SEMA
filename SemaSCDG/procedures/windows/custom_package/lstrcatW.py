import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class lstrcatW(angr.SimProcedure):
    def run(self, string1, string2):
        if string1.symbolic or string2.symbolic:
            return string1
            
        try:
            first_str = self.state.mem[string1].wstring.concrete
        except:
            lw.info("string1 not resolvable")
            first_str = ""
        try:
            second_str = self.state.mem[string2].wstring.concrete
        except:
            lw.info("string2 not resolvable")
            second_str = ""
                
        new_str = first_str + second_str + "\0"
        new_str = self.state.solver.BVV(new_str.encode("utf-16le"))
        self.state.memory.store(string1, new_str)
        return string1
