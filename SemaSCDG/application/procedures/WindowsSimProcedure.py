import angr
import logging
import os

from clogging.CustomFormatter import CustomFormatter
from CustomSimProcedure import CustomSimProcedure

from angr.procedures import SIM_LIBRARIES
from angr.calling_conventions import SimCCMicrosoftAMD64


class WindowsSimProcedure(CustomSimProcedure):

    def __init__(self, verbose = False):
        super().__init__(verbose)
        self.log = None
        self.setup("windows")

    # Set up the logger
    def config_logger(self):
        if self.log is None:
            self.log_level = os.environ["LOG_LEVEL"]
            logger = logging.getLogger("WindowsSimProcedure")
            ch = logging.StreamHandler()
            ch.setLevel(self.log_level)
            ch.setFormatter(CustomFormatter())
            logger.addHandler(ch)
            logger.propagate = False
            logger.setLevel(self.log_level)
            self.log = logger
    
    # Set properly the value in the sim_proc dictionary when meeting an ALT_NAME argument
    def deal_with_alt_names(self, pkg_name, proc):
        new_proc = proc # TODO clone
        new_proc.__name__ = proc.ALT_NAMES
        new_proc.__qualname__ = proc.ALT_NAMES
        self.sim_proc[pkg_name][proc.ALT_NAMES] = new_proc
    
    # Check if the name is present in angr simprocedures
    def name_in_angr_simproc(self, name, simproc_names):
        for i in simproc_names:
            if name in angr.SIM_PROCEDURES[i]:
                return True
        return False

    # Hooking method for static library
    def custom_hook_static(self, proj):
        if self.verbose: self.log.info("custom_hook_static_windows")
        proj.loader
        symbols = proj.loader.symbols

        custom_pack = self.sim_proc["custom_package"]

        manual_link = {
            "LoadLibraryA": custom_pack["LoadLibraryA"],
            "LoadLibraryExA": custom_pack["LoadLibraryExA"],
            "LoadLibraryW": custom_pack["LoadLibraryW"],
            "LoadLibraryExW": custom_pack["LoadLibraryExW"],
            "GetProcAddress": custom_pack["GetProcAddress"],
            "GetModuleHandleExW": custom_pack["GetModuleHandleExW"],
            "GetModuleHandleExA": custom_pack["GetModuleHandleExA"],
            "GetModuleHandleW": custom_pack["GetModuleHandleW"],
            "GetModuleHandleA": custom_pack["GetModuleHandleA"],
            "GetModuleFileNameA": custom_pack["GetModuleFileNameA"],
            "GetModuleFileNameW": custom_pack["GetModuleFileNameW"],
            # "GetModuleFileNameExA": custom_pack["GetModuleFileNameExA"],
            # "GetModuleFileNameExW": custom_pack["GetModuleFileNameExW"],
        }

        ignore_simproc = {"LoadLibraryA", "LoadLibraryW"}
        simproc64 = {"fopen64": "fopen"}
        angr_simproc_to_check = [
            "glibc",
            "libc",
            "posix",
            "linux_kernel",
            "win32",
            "win_user32",
            "ntdll",
            "msvcr"
        ]
        
        #TODO : Try with and without the "if x86 : if windows"
        for symb in symbols:
            name = symb.name
            if name in manual_link:
                proj.unhook(symb.rebased_addr)
                if proj.arch.name == "X86":
                    self.std_sim_proc_hook(proj, symb.rebased_addr, manual_link[name])
                else:
                    proj.hook(symb.rebased_addr, manual_link[name](cc=SimCCMicrosoftAMD64(proj.arch)))
            elif not name or name in ignore_simproc:
                pass
            boo = False
            for simproc_to_check in angr_simproc_to_check:
                if name in angr.SIM_PROCEDURES[simproc_to_check]:
                    boo = True
                    if proj.arch.name == "X86":
                        if proj.simos.name == "windows":
                            proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES[simproc_to_check][name]())
                    else:
                        self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES[simproc_to_check][name])
                    break
            if boo : continue
            if name in simproc64:
                if proj.arch.name == "X86":
                    if proj.simos.name == "windows":
                        proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["libc"][simproc64[name]]())
                else:
                    self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES["libc"][simproc64[name]])
            elif "ordinal" in name:
                # ex : ordinal.680.b'shell32.dll'
                # import pdb; pdb.set_trace()
                part_names = name.split(".")
                lib_part = part_names[2][2:] + ".dll"
                ord_part = part_names[1]
                if self.verbose:
                    self.log.info(lib_part)
                    self.log.info(ord_part)
                # symb.name = self.system_call_table[lib_part][ord_part]['name']

    # Hooking method for procedures in custom package and hooking of project symbols
    def custom_hook_windows_symbols(self, proj):
        """_summary_
        TODO CH
        Args:
            proj (_type_): _description_
        """
        # self.ANG_CALLING_CONVENTION = {"__stdcall": SimCCStdcall, "__cdecl": SimCCCdecl}
        if self.verbose: self.log.info("custom_hook_windows_symbols")
        proj.loader
        symbols = proj.loader.symbols

        excluded_simproc_name = ["win32","win_user32","ntdll","msvcr"]
        special_case_simproc_name = ["posix", "linux_kernel", "libc"]


        for lib in self.system_call_table:
            for key in self.system_call_table[lib]:
                name = self.system_call_table[lib][key]["name"]
                if (not self.name_in_angr_simproc(name, excluded_simproc_name) and len(self.system_call_table[lib][key]["arguments"]) != 0):
                    for symb in symbols:
                        if (name == symb.name and (not self.name_in_angr_simproc(name, special_case_simproc_name))
                            and name not in self.sim_proc["custom_package"]
                        ):
                            proj.hook_symbol(
                                name, SIM_LIBRARIES[lib].get(name, proj.arch)
                            )
                        if symb.name in self.sim_proc["custom_package"]:
                            proj.unhook(symb.rebased_addr)
                            if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name]):
                                if symb.name not in self.CDECL_EXCEPT:
                                    self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])
                                else:
                                    self.exception_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])

                        if symb.name and "ordinal" in symb.name:
                            # ex : ordinal.680.b'shell32.dll'
                            part_names = symb.name.split(".")
                            lib_part = part_names[2][2:] + ".dll"
                            ord_part = part_names[1]
                            try:
                                real_name = self.system_call_table[lib_part][ord_part]["name"]
                            except:
                                real_name = "nope"

                            if real_name == "nope":
                                pass
                            elif (real_name in self.sim_proc["custom_package"]):
                                proj.unhook(symb.rebased_addr)
                                if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][name]):
                                    self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][real_name])
                            elif lib_part == lib:
                                proj.unhook(symb.rebased_addr)
                                proj.hook(
                                    symb.rebased_addr,
                                    SIM_LIBRARIES[lib].get(real_name, proj.arch),
                                )

    # Hook of the type "SimCCMicrosoftAMD64" when project architecture is AMD64
    def amd64_sim_proc_hook(self, project, name, sim_proc):
        if project.arch.name == "AMD64":
            project.hook(
                name,
                sim_proc(
                    cc=SimCCMicrosoftAMD64(project.arch)
                ),
            )
            return True
        return False
    
    # Use the ddl loader to get the syscall table
    def load_syscall_table(self, proj):
        self.system_call_table = self.ddl_loader.load(proj, False , None)