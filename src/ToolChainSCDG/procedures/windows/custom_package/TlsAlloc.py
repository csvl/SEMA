import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


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
