import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class TlsSetValue(angr.SimProcedure):
    KEY = "win32_tls"

    def mutate_dict(self,state, KEY):
        d = dict(state.globals.get(KEY, {}))
        state.globals[KEY] = d
        return d

    def has_index(self,state, idx, KEY):
        if KEY not in state.globals:
            return False
        return idx in state.globals[KEY]

    def run(self, index, value):
        conc_indexs = self.state.solver.eval_upto(index, 2)
        if len(conc_indexs) != 1:
            raise angr.errors.SimValueError(
                "Can't handle symbolic index in TlsSetValue/FlsSetValue"
            )
        conc_index = conc_indexs[0]

        if not self.has_index(self.state, conc_index, self.KEY):
            return 0

        self.mutate_dict(self.state, self.KEY)[conc_index] = value
        return 1
