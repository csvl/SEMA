# import angr
# import claripy

# class GetCurrentProcess(angr.SimProcedure):
#     def run(self):
#         return self.state.solver.BVV(0xffffffff, self.state.arch.bits)