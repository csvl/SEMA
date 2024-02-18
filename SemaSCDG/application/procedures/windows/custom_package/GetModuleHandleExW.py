import logging
import sys
import angr

from procedures.WindowsSimProcedure import WindowsSimProcedure

import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetModuleHandleExW(angr.SimProcedure):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].wstring.concrete
        if hasattr(lib, "decode"):
            lib = lib.decode("utf-16-le")
        return lib

    def run(self, flag, lib_ptr, module_ptr):
        call_sim = WindowsSimProcedure()
         
        if self.state.solver.is_true(lib_ptr == 0):
            # import pdb; pdb.set_trace()
            return self.project.loader.main_object.mapped_base

        proj = self.state.project
        lib = self.decodeString(lib_ptr)
        lib = str(lib).lower()
        lw.debug(
            "GetModuleHandleExW: {}  asks for handle to {}".format(
                self.display_name, lib
            )
        )

        # We will create a fake symbol to represent the handle to the library
        # Check first if we already did that before
        symb = proj.loader.find_symbol(lib)
        if symb:
            # Yeah !
            self.state.globals["loaded_libs"][symb.rebased_addr] = lib
            self.state.memory.store(
                module_ptr, symb.rebased_addr
            )  # ,endness=self.arch.memory_endness)
            return symb.rebased_addr
        else:
            # lw.debug('GetModuleHandleExW: Symbol not found')
            extern = proj.loader.extern_object
            addr = extern.get_pseudo_addr(lib)
            self.state.globals["loaded_libs"][addr] = lib

            try:
                # import pdb; pdb.set_trace()
                str_lib = str(lib)
                if ".dll" not in lib:
                    lib = str_lib + ".dll"
                self.state.project.loader.requested_names.add(lib)
                call_sim.loadlibs_proc(
                    call_sim.ddl_loader.load(self.state.project), self.state.project
                )
            except Exception as inst:
                # self.log.warning(type(inst))    # the exception instance
                lw.warning(inst)  # __str__ allows args to be printed directly,
                exc_type, exc_obj, exc_tb = sys.exc_info()
                # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                lw.warning(exc_type, exc_obj)
                lw.debug("GetModuleHandleExW: Fail to load dynamically lib " + str(lib))
                exit(-1)

            # import pdb; pdb.set_trace()
            self.state.memory.store(
                module_ptr, addr
            )  # ,endness=self.arch.memory_endness)
            # import pdb; pdb.set_trace()
            return addr
        return lib_ptr
        # return self.load(lib)

# Was triggering errors because of encoding that can not be decoded in utf-8
#class GetModuleHandleExW(GetModuleHandleExW):
    # def decodeString(self, ptr):
    #     lib = self.state.mem[ptr].string.concrete.decode("utf-8")
    #     return lib
