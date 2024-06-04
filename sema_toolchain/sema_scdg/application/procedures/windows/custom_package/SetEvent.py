import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import claripy

class SetEvent(angr.SimProcedure):
    def run(self, hEvent):
        # Get the value of the event handle
        event_handle = self.state.solver.eval(hEvent)

        # # Set the event object to signaled
        # self.state.event_manager.add_event(event_handle)

        # Set the return value to indicate success
        return 0x1 #claripy.BVV(1, self.state.arch.bits)
