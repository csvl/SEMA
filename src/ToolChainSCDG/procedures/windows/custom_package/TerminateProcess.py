import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class TerminateProcess(angr.SimProcedure):
    NO_RET = True

    def run(self, handle, exit_code):

        if "GetCurrentProcess" in handle._encoded_name.decode("utf-8"):
            self.exit(exit_code)
        else:
            # import pdb; pdb.set_trace()
            pass
