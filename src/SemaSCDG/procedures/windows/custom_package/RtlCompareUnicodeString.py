import logging
import angr
import archinfo 

lw = logging.getLogger("CustomSimProcedureWindows")


class RtlCompareUnicodeString(angr.SimProcedure):
    def run(self, arg1, arg2, arg3):
        addr1 = self.state.memory.load(arg1+4,4,endness=archinfo.Endness.LE)
        if not addr1.symbolic:
            print(self.state.mem[addr1].wstring.concrete)
        addr2 = self.state.memory.load(arg2+4,4,endness=archinfo.Endness.LE)
        if not addr2.symbolic:
            print(self.state.mem[addr2].wstring.concrete)
            
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
