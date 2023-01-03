import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetTokenInformation(angr.SimProcedure):

    def run(
        self,
        TokenHandle,
        TokenInformationClass,
        TokenInformation,
        TokenInformationLength,
        ReturnLength
    ):
        ptr = self.state.solver.BVV(0x1,32)
        self.state.memory.store(TokenInformation,ptr)
        return 0x1
