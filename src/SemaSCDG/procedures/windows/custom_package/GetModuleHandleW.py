import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class GetModuleHandleW(angr.SimProcedure):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].wstring.concrete
        if hasattr(lib, "decode"):
            lib = lib.decode("utf-16-le")
        return lib

    def run(self, lib_ptr):

        if lib_ptr.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        if self.state.solver.is_true(lib_ptr == 0):
            return self.project.loader.main_object.mapped_base

        proj = self.state.project
        lib = self.decodeString(lib_ptr)
        lib = str(lib).lower()
        lw.info(
            "GetModuleHandleW: {}  asks for handle to {}".format(self.display_name, lib)
        )

        # We will create a fake symbol to represent the handle to the library
        # Check first if we already did that before
        symb = proj.loader.find_symbol(lib)
        if symb:
            # Yeah !
            self.state.globals["loaded_libs"][symb.rebased_addr] = lib
            return symb.rebased_addr
        else:
            # lw.info('GetModuleHandleW: Symbol not found')
            extern = proj.loader.extern_object
            addr = extern.get_pseudo_addr(lib)
            self.state.globals["loaded_libs"][addr] = lib
            # import pdb; pdb.set_trace()
            return addr
        return lib_ptr
        # return self.load(lib)
