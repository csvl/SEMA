import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)


class _local_unwind2(angr.SimProcedure):
    def run(self, frame_pointer, stop):
        lw.debug("enter _local_unwind2")
        if self.state.solver.eval(stop) == 0xFFFFFFFF:
            lw.debug("free frame pointer {}".format(frame_pointer))
            self.state.heap._free(frame_pointer)

        return 1
