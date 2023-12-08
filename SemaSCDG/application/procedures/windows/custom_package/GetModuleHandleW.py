import logging
import angr

from procedures.WindowsSimProcedure import WindowsSimProcedure
from procedures.CustomSimProcedure import CustomSimProcedure

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
log_level = config['SCDG_arg'].get('log_level')
lw.setLevel(log_level)


class GetModuleHandleW(angr.SimProcedure):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].wstring.concrete
        # if hasattr(lib, "decode"):
        #     lib = lib.decode("utf-16-le")
        return lib

    def run(self, lib_ptr):
        call_sim = WindowsSimProcedure(log_level)
            
        if lib_ptr.symbolic:
            lw.debug("Symbolic lib")
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        if self.state.solver.is_true(lib_ptr == 0):
            lw.debug("GetModuleHandleW: NULL")
            return self.project.loader.main_object.mapped_base

        proj = self.state.project
        lib = self.decodeString(lib_ptr).lower()
        #lib = str(lib).lower()
        lw.debug(
            "GetModuleHandleW: {}  asks for handle to {}".format(self.display_name, lib)
        )
        if(lib in CustomSimProcedure.EVASION_LIBS):
            lw.debug("Evasion library detected: {}".format(lib))
            #self.state.plugin_evasion.libraries.append(lib)
            return 0
        # We will create a fake symbol to represent the handle to the library
        # Check first if we already did that before
        symb = proj.loader.find_symbol(lib)
        if symb:
            # Yeah !
            self.state.globals["loaded_libs"][symb.rebased_addr] = lib
            return symb.rebased_addr
        else:
            # lw.debug('GetModuleHandleW: Symbol not found')
            extern = proj.loader.extern_object
            addr = extern.get_pseudo_addr(lib)
            self.state.globals["loaded_libs"][addr] = lib
            # import pdb; pdb.set_trace()
            return addr
        return lib_ptr
        # return self.load(lib)
