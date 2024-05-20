import angr
import claripy

class SetErrorMode(angr.SimProcedure):
    def run(self, uMode):
        # Treat uMode as a concrete value or a symbolic variable of type UINT
        if self.state.solver.symbolic(uMode):
            uMode = self.state.solver.Unconstrained("uMode", self.state.arch.bits)
        # Store the value of uMode in the global error mode variable
        # self.state.globals['error_mode'] = uMode
        # Return 0 to indicate success
        return 0x0 # self.state.solver.BVV(0, self.state.arch.bits)
