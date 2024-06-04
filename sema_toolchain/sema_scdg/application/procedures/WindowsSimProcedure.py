import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr
import logging
import os
from datetime import datetime

from clogging.CustomFormatter import CustomFormatter
from CustomSimProcedure import CustomSimProcedure

from angr.procedures import SIM_LIBRARIES
from angr.calling_conventions import SimCCMicrosoftAMD64

try:
    log_level = os.environ["LOG_LEVEL"]
    logger = logging.getLogger("WindowsSimProcedure")
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    logger.propagate = False
    logger.setLevel(log_level)
except Exception as e:
    print(e)
    
class WindowsSimProcedure(CustomSimProcedure):
    """
    Defines methods for applying custom simulation procedures and hooks in a Windows environment.

    This class includes methods for setting up the logger, dealing with alternative names, checking for names in angr simprocedures, applying static hooks, and customizing hooks for Windows symbols.
    """

    def __init__(self, verbose = False):
        """
        Initializes a Windows simulation procedure with optional verbosity.

        This method sets up the Windows environment for simulation procedures by initializing the logger and configuring the environment for Windows-specific procedures.
        """
        super().__init__(verbose)
        self.log = None
        self.setup("windows")

    def config_logger(self):
        """
        Configures the logger if it is not already set.

        This function sets up the logger for the Windows simulation procedure, initializing it with the specified log level if it is not already defined.
        """
        if self.log is None:
            self.log = logger
            self.log_level = log_level

    def deal_with_alt_names(self, pkg_name, proc):
        """
        Deals with alternative names by updating the simulation procedures dictionary with the alternative name.

        This function assigns the alternative name to the procedure and adds
        """
        new_proc = proc # TODO clone
        new_proc.__name__ = proc.ALT_NAMES
        new_proc.__qualname__ = proc.ALT_NAMES
        self.sim_proc[pkg_name][proc.ALT_NAMES] = new_proc

    def name_in_angr_simproc(self, name, simproc_names):
        """
        Checks if a given name is present in the angr simulation procedures for the specified simulation procedure names.

        This function iterates through the provided simulation procedure names to determine if the given name exists in the angr simulation procedures, returning True if found, otherwise False.
        """
        return any(name in angr.SIM_PROCEDURES[i] for i in simproc_names)

    def custom_hook_static(self, proj):
        """
        Applies custom static hooks to symbols in the project, handling Windows-specific procedures.

        This function customizes hooking for specific Windows symbols, including manual linking, checking for existing angr simulation procedures, and applying appropriate hooks based on the project architecture and symbol names.
        """
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
                part_names = name.split(".")
                lib_part = part_names[2][2:] + ".dll"
                ord_part = part_names[1]
                if self.verbose:
                    self.log.info(lib_part)
                    self.log.info(ord_part)

    def custom_hook_windows_symbols(self, proj):
        """
        Customizes hooking for Windows symbols in the project, handling special cases and excluded names.

        This function applies custom procedures to symbols, handles special cases, and excludes specific names when hooking Windows symbols in the project.
        """
        if self.verbose: self.log.info("custom_hook_windows_symbols")
        proj.loader

        excluded_simproc_name = ["win32","win_user32","ntdll","msvcr"]
        special_case_simproc_name = ["posix", "linux_kernel", "libc"]

        symbols_set = set(proj.loader.symbols)
        self.handle_custom_package_hooks(proj, symbols_set)

        for lib in self.system_call_table:
            for key in self.system_call_table[lib]:
                name = self.system_call_table[lib][key]["name"]
                if (not self.name_in_angr_simproc(name, excluded_simproc_name) and len(self.system_call_table[lib][key]["arguments"]) != 0):
                    for symb in symbols_set:
                        if (name == symb.name and (not self.name_in_angr_simproc(name, special_case_simproc_name)) and name not in self.sim_proc["custom_package"]):
                            proj.hook_symbol(
                                name, SIM_LIBRARIES[lib].get(name, proj.arch)
                            )
                        if symb.name and "ordinal" in symb.name:
                            # ex : ordinal.680.b'shell32.dll'
                            self.handle_ordinal(proj, symb, lib, name)

    def handle_custom_package_hooks(self, proj, symbols_set):
        """
        Handles custom package hooks for symbols in the project.

        This function iterates through a set of symbols and applies custom procedures from the custom package, handling different cases based on the symbol name and exceptions.
        """
        for symb in symbols_set:
            if symb.name in self.sim_proc["custom_package"]:
                proj.unhook(symb.rebased_addr)
                if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name]):
                    if symb.name not in self.CDECL_EXCEPT:
                        self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])
                    else:
                        self.exception_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])

    def handle_ordinal(self, proj, symb, lib, name):
        """
        Handles ordinal symbols by resolving and applying the appropriate procedures in the project.

        This function processes ordinal symbols by extracting the necessary information, determining the real name, and applying the corresponding procedures in the project based on the library and ordinal part.
        """
        part_names = symb.name.split(".")
        lib_part = f"{part_names[2][2:]}.dll"
        ord_part = part_names[1]
        try:
            real_name = self.system_call_table[lib_part][ord_part]["name"]
        except Exception:
            real_name = "nope"

        if real_name != "nope":
            if (real_name in self.sim_proc["custom_package"]):
                proj.unhook(symb.rebased_addr)
                if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][name]):
                    self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][real_name])
            elif lib_part == lib:
                proj.unhook(symb.rebased_addr)
                proj.hook(
                    symb.rebased_addr,
                    SIM_LIBRARIES[lib].get(real_name, proj.arch),
                )

    def amd64_sim_proc_hook(self, project, name, sim_proc):
        """
        Applies a simulation procedure hook for AMD64 architecture in the project.

        This function checks if the project architecture is AMD64 and hooks the specified name with the provided simulation procedure, applying the appropriate calling convention.
        """
        if project.arch.name == "AMD64":
            project.hook(
                name,
                sim_proc(
                    cc=SimCCMicrosoftAMD64(project.arch)
                ),
            )
            return True
        return False

    def load_syscall_table(self, proj):
        """
        Loads the syscall table using the DLL loader in the project.

        This function initializes the system call table by loading it from the project using the DLL loader.
        """
        self.system_call_table = self.ddl_loader.load(proj, False , None)
