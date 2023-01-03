import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class AdjustTokenPrivileges(angr.SimProcedure):
    def run(
        self,
        TokenHandle,
        DisableAllPrivileges,
        NewState,
        BufferLength,
        PreviousState,
        ReturnLength
    ):
        return 0x1
