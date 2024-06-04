import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
import archinfo
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


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
