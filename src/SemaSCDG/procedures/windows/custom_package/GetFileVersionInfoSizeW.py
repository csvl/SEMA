import angr
import claripy

class GetFileVersionInfoSizeW(angr.SimProcedure):
    def run(self, lptstrFilename, lpdwHandle):
        # Treat lptstrFilename as a concrete value or a symbolic variable of type LPCWSTR
        if self.state.solver.symbolic(lptstrFilename):
            lptstrFilename = self.state.solver.Unconstrained("lptstrFilename", 8 * 260)
        # Treat lpdwHandle as a concrete value or a symbolic variable of type LPDWORD
        if self.state.solver.symbolic(lpdwHandle):
            lpdwHandle = self.state.solver.Unconstrained("lpdwHandle", self.state.arch.bits)
        # Set the value of lpdwHandle to a non-zero value to indicate success
        self.state.memory.store(lpdwHandle, self.state.solver.BVV(1, self.state.arch.bits))
        # Return a symbolic value of type UINT
        return 0x20 #self.state.solver.Unconstrained("dwLen", self.state.arch.bits)
