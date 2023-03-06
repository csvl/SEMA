# import angr

# class OpenProcess(angr.SimProcedure):
#     def run(self, dwDesiredAccess, bInheritHandle, dwProcessId):
#         return  self.state.solver.BVS('handle_{}'.format(self.display_name), self.state.arch.bits)