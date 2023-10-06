import angr 
import claripy

THREAD_PRIORITY_ABOVE_NORMAL = 1
THREAD_PRIORITY_BELOW_NORMAL = -1
THREAD_PRIORITY_HIGHEST = 2
THREAD_PRIORITY_IDLE = -15
THREAD_PRIORITY_LOWEST = -2
THREAD_PRIORITY_NORMAL = 0
THREAD_PRIORITY_TIME_CRITICAL = 15

class GetThreadPriority(angr.SimProcedure):
    def run(self, hThread):
        retval = self.state.solver.BVS(
                    "retval_{}".format(self.display_name), self.arch.bits
        ) 
        # AttributeError: 'NotImplementedType' object has no attribute 'split'
        # constraint = self.state.solver.Or([retval == THREAD_PRIORITY_ABOVE_NORMAL,retval == THREAD_PRIORITY_BELOW_NORMAL,retval == THREAD_PRIORITY_HIGHEST,retval == THREAD_PRIORITY_IDLE,retval == THREAD_PRIORITY_LOWEST,retval == THREAD_PRIORITY_NORMAL,retval == THREAD_PRIORITY_TIME_CRITICAL])
        # self.state.add_constraints(constraint)
        return retval