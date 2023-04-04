import angr

class VarBstrFromBool(angr.SimProcedure):
    def run(self,pbVal, lcid, dwFlags, pbstrOut):
        pbVal = self.state.solver.eval(pbVal)
        if pbVal == 0:
            bstr = "false".encode("utf-8") + b"\x00"
        else: 
            bstr = "true".encode("utf-8") + b"\x00"
        self.state.memory.store(pbstrOut,bstr)
        return 0x00000000