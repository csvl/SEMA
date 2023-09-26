import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class CloseHandle(angr.SimProcedure):
    def run(self, hObject):
        return 0x1
