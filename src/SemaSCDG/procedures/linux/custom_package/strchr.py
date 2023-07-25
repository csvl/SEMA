import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

class strrchr(angr.SimProcedure):
    # return address of the last occurrence
    # official angr version is more symbolic
    def run(self, string, searchedChar):
        print("+"*250)

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
        
        offset = len(first_str)
        for char in first_str[::-1]:
            if char == searchedChar_conc:
                return offset
            offset -= 1

        return string+offset