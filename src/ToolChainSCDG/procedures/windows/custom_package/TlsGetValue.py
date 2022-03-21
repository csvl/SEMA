import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class TlsGetValue(angr.SimProcedure):
    KEY = "win32_tls"

    def has_index(self, state, idx, KEY):
        if KEY not in state.globals:
            return False
        return idx in state.globals[KEY]

    def run(self, index):
        conc_indexs = self.state.solver.eval_upto(index, 2)
        if len(conc_indexs) != 1:
            raise angr.errors.SimValueError(
                "Can't handle symbolic index in TlsGetValue/FlsGetValue"
            )
        conc_index = conc_indexs[0]

        if not self.has_index(self.state, conc_index, self.KEY):
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        lw.info(
            "TlsGetValue - Stored value :"
            + str(self.state.globals[self.KEY][conc_index])
        )
        return self.state.globals[self.KEY][conc_index]
