import angr 

class ReleaseSemaphore(angr.SimProcedure):
    def run(self, hSemaphore, lReleaseCount, lpPreviousCount):

        # # Treat hSemaphore as an unconstrained symbolic variable of type HANDLE
        # hSemaphore = self.state.solver.Unconstrained("hSemaphore", self.state.arch.bits)

        # # Constrain lReleaseCount to be non-negative
        # self.state.add_constraints(lReleaseCount >= 0)

        # # Treat lpPreviousCount as an unconstrained symbolic variable of type LPDWORD
        # lpPreviousCount = self.state.solver.Unconstrained("lpPreviousCount", self.state.arch.bits)

        # Return true to indicate success
        return 0x1 #self.state.solver.BVV(1, 32)