import angr
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
except Exception as e:
    print(e)

class ExitThread(angr.SimProcedure):
    NO_RET = True

    def run(self, dwExitCode):
        lw.debug("ExitThread")
        self.exit(exit_code=dwExitCode)
