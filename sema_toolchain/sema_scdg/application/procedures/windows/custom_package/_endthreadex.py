import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr

class _endthreadex(angr.SimProcedure):
    def run(self, exit_code):
        # Set the exit code of the thread
        #self.state.thread.exit_status = exit_code

        # Terminate the thread
        self.exit(exit_code)
