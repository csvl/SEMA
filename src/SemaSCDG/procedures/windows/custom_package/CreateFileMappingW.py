import angr
import logging 

l = logging.getLogger("CustomSimProcedureWindows")

class CreateFileMappingW(angr.SimProcedure):
    def run(self, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
        # Just return a symbolic value as a placeholder
        returned = self.state.solver.BVS('file_mapping_handle_{}'.format(self.display_name), self.arch.bits)
        
        if self.state.solver.eval(hFile) == 0xffffffffffffffff: #  system paging file
            l.info("pagefile")
            simfd = self.state.posix.open("pagefile.sys", self.state.solver.BVV(2, self.arch.bits))
        else:
            l.info("not pagefile")
            simfd = self.state.posix.get_fd(hFile)
            if not simfd:
                self.state.posix.open("pagefile.sys", self.state.solver.BVV(2, self.arch.bits))
               
        l.info(simfd)
             
        self.state.globals["files"][returned] = simfd
            
        return returned
