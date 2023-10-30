import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetDriveTypeA(angr.SimProcedure):
    def run(self, lpRootPathName):
        # return 0x3

        drive_type = self.state.solver.BVV(3, self.arch.bits)  # 3 corresponds to DRIVE_FIXED

        return drive_type
