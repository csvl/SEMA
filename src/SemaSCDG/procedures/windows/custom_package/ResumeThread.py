import angr
class ResumeThread(angr.SimProcedure):
    def run(self, hThread):
        # Do nothing - return value not needed for symbolic execution
        r = self.state.solver.BVS('ret_{}'.format(self.display_name), self.arch.bits)
        self.state.solver.add(r >= 0)
        self.state.solver.add(r <= 4)
        return r
