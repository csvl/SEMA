import angr
import logging 

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))

class CreateFileMappingW(angr.SimProcedure):
    def run(self, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
        # Just return a symbolic value as a placeholder
        returned = self.state.solver.BVS('file_mapping_handle_{}'.format(self.display_name), self.arch.bits)
        
        if self.state.solver.eval(hFile) == 0xffffffffffffffff: #  system paging file
            lw.debug("pagefile")
            simfd = self.state.posix.open("pagefile.sys", self.state.solver.BVV(2, self.arch.bits))
            name = "pagefile.sys"
        else:
            lw.debug("not pagefile")
            simfd = self.state.posix.get_fd(hFile)
            name = self.state.mem[lpName].wstring.concrete
            name = name.encode("utf-8")
            if not simfd:
                simfd = self.state.posix.open("pagefile.sys", self.state.solver.BVV(2, self.arch.bits))
                name = "pagefile.sys"
               
        lw.debug(simfd)
             
        self.state.globals["files"][simfd] = name
        
        self.state.globals["files_fd"][returned] = simfd
            
        return returned
