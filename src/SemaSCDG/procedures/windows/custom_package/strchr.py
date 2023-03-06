import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class strchr(angr.SimProcedure):
    # return address of the first occurrence
    def run(self, string, searchedChar):

        if string.symbolic or searchedChar.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )
                  
        first_str = self.state.mem[string].string.concrete

        if hasattr(first_str, "decode"):
            try:
                first_str = first_str.decode("utf-8")
            except:
                first_str = first_str.decode("utf-8",errors="ignore")
                
        searchedChar_conc = self.state.solver.eval(searchedChar)
        
        offset = 0
        for char in first_str:
            if char == searchedChar_conc:
                return offset
            offset += 1

        return string+offset
