import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class TlsAlloc(angr.SimProcedure):
    KEY = "win32_tls"

    def mutate_dict(self,state, KEY):
        d = dict(state.globals.get(KEY, {}))
        state.globals[KEY] = d
        return d

    def run(self):
        d = self.mutate_dict(self.state, self.KEY)
        new_key = len(d) + 1
        d[new_key] = self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
        return new_key
