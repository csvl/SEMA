import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class chdir(angr.SimProcedure):
    def run(self, buf):
        cwd = self.state.mem[buf].string.concrete  # FIX ANGR ERROR
        # l.info('chdir(%r)', cwd)
        self.state.fs.cwd = cwd
        return 0
