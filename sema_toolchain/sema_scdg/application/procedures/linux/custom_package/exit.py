import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class exit(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self, exit_code):
        self.exit(exit_code)
