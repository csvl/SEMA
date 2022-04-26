import json
import logging
import sys
import angr

# import procedures.dll_table as dll
from angr.calling_conventions import SimCCStdcall
from angr.procedures import SIM_LIBRARIES

# from ...CustomSimProcedure import *
lw = logging.getLogger("CustomSimProcedureWindows")

# TODO some errors in this custom procedure

class GetProcAddress(angr.SimProcedure):
    def run(self, lib_handle, name_addr):
        call_sim = None
        try:
            from procedures.CustomSimProcedure import CustomSimProcedure  # TODO fix  # TODO fix
            call_sim = CustomSimProcedure([], [],False)
        except Exception as e:
            from ....procedures.CustomSimProcedure import CustomSimProcedure  # TODO fix  # TODO fix
            call_sim = CustomSimProcedure([], [],True)
        # Let's take the name of the function we are looking for and check if a symbol already exists.

        name = self.state.mem[name_addr].string.concrete
        if not isinstance(name, str):
            try:
                name = name.decode("utf-8")
            except:
                name = name.decode("utf-8",errors="ignore")
        lw.info("GetProcAddress: " + str(name))

        # import pdb; pdb.set_trace()
        proj = self.project
        symb = proj.loader.find_symbol(name)
        if symb:
            # Yeah ! Symbols exist and it is already hooked (normaly)
            return symb.rebased_addr

        lib_addr = self.state.solver.eval(lib_handle)
        # import pdb; pdb.set_trace()
        if self.state.solver.eval(lib_addr) in self.state.globals["loaded_libs"]:
            lib = self.state.globals["loaded_libs"][lib_addr]
            test = lib + ".dll"
            if lib not in SIM_LIBRARIES and (test in SIM_LIBRARIES):
                lib = lib + ".dll"
        else:
            try:
                lib = self.state.mem[lib_handle].string.concrete.decode("utf-8")
            except:
                lib = self.state.mem[lib_handle].wstring.concrete
                
            test = lib + ".dll"
            if lib not in SIM_LIBRARIES and (test in SIM_LIBRARIES):
                lib = test
        if lib not in SIM_LIBRARIES:
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
                lw.info("GetProcAddress: Fail to load dynamically lib " + str(lib))
                exit(-1)

        lw.info("GetProcAddress - Query to lib : " + str(lib))

        if symb:
            # Yeah ! Symbols exist and it is already hooked (normally)
            return symb.rebased_addr
        else:
            lw.info("GetProcAddress: Symbol not found")
            extern = proj.loader.extern_object
            addr = extern.get_pseudo_addr(name)

            if name in call_sim.custom_simproc_windows:
                proj.hook_symbol(
                    name,
                    call_sim.custom_simproc_windows[name](cc=SimCCStdcall(proj.arch)),
                )
            elif lib in SIM_LIBRARIES:
                # import pdb; pdb.set_trace()
                proj.hook_symbol(name, SIM_LIBRARIES[lib].get(name, self.state.arch))
            else:
                return self.state.solver.BVS(
                    "retval_{}".format(self.display_name), self.arch.bits
                )
            return addr

    def retrieve_func(self, lib, name):
        from procedures.linux.CustomSimProcedureLinux import (
            gen_simproc0,
            gen_simproc1,
            gen_simproc2,
            gen_simproc3,
            gen_simproc4,
            gen_simproc5,
            gen_simproc6,
            gen_simproc7,
        )

        generic = {}
        generic["0"] = gen_simproc0
        generic["1"] = gen_simproc1
        generic["2"] = gen_simproc2
        generic["3"] = gen_simproc3
        generic["4"] = gen_simproc4
        generic["5"] = gen_simproc5
        generic["6"] = gen_simproc6
        generic["7"] = gen_simproc7

        with open("./calls/" + str(lib) + ".json", "r") as fp:
            data = json.load(fp)
            if name in data:
                num_args = len(data[name]["arguments"])
                sim_proc = generic[str(num_args)]()
                sim_proc.name = name
                return sim_proc
