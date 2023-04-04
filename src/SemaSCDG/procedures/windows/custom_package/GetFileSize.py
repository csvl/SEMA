import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetFileSize(angr.SimProcedure):
    def run(self, hFile, lpFileSizeHigh):
        if hFile.symbolic:
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val != 0xFFFFFFFF)
            return ret_val
        simfd = self.state.posix.get_fd(hFile)
        # import pdb; pdb.set_trace()
        if simfd is None:
            lw.info("GetFileSize: could not find fd")
            return self.state.solver.BVS("retval_{}".format(self.display_name),  self.arch.bits)
        lw.info(
            "GetFileSize: {}  asks file size of {}".format(self.display_name, hFile)
        )
        size = simfd.size()
        if not size.symbolic and self.state.solver.eval(size) != 0:
            return size
        else:
            ret_val = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
            self.state.solver.add(ret_val > 0)
            self.state.solver.add(ret_val < 0x100000)
            return ret_val

