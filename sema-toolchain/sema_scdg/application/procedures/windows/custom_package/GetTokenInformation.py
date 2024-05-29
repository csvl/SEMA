import logging
import angr
import archinfo
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetTokenInformation(angr.SimProcedure):

    def run(
        self,
        TokenHandle,
        TokenInformationClass,
        TokenInformation,
        TokenInformationLength,
        ReturnLength
    ):
        length = self.state.solver.eval(TokenInformationLength)
        ptr = self.state.solver.BVS("TokenInformation_{}".format(self.display_name), length*8)
        self.state.memory.store(TokenInformation,ptr,endness=archinfo.Endness.LE)
        ptr = self.state.solver.BVV(length, 32)
        self.state.memory.store(ReturnLength,ptr,endness=archinfo.Endness.LE)
        return 0x1
